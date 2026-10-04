package cmd

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cometbft/cometbft/crypto"
	"github.com/stretchr/testify/require"

	"github.com/voluzi/cosmosigner/internal/backend"
)

type pinStartupBackend struct {
	backend.KeyBackend
	phase         string
	cause         error
	cancelOnError context.CancelFunc
	contextStarts *atomic.Int32
	failedCalls   atomic.Int32
	signs         atomic.Int32
	closed        chan struct{}
}

func (b *pinStartupBackend) PubKey() (crypto.PubKey, error) {
	if b.contextStarts.Load() != 0 {
		return nil, errors.New("signal context started before context-free public-key discovery")
	}
	return b.KeyBackend.PubKey()
}

func (b *pinStartupBackend) fail() error {
	b.failedCalls.Add(1)
	if b.cancelOnError != nil {
		b.cancelOnError()
	}
	return fmt.Errorf("token login: %w", b.cause)
}

func (b *pinStartupBackend) VerifyCanSign(context.Context) error {
	if b.phase == "preflight" {
		return b.fail()
	}
	return nil
}

func (b *pinStartupBackend) ClaimCluster(ctx context.Context, id string) error {
	if b.phase == "claim" {
		return b.fail()
	}
	return b.KeyBackend.ClaimCluster(ctx, id)
}

func (b *pinStartupBackend) Sign(msg []byte) ([]byte, error) {
	b.signs.Add(1)
	return b.KeyBackend.Sign(msg)
}

func (b *pinStartupBackend) Close() error {
	err := b.KeyBackend.Close()
	close(b.closed)
	return err
}

func TestStartPINFailureLifecycle(t *testing.T) {
	nonPIN := errors.New("token unavailable")
	for _, tc := range []struct {
		name           string
		phase          string
		http           bool
		initializeOnly bool
		cancelOnError  bool
		deadline       bool
		cause          error
	}{
		{name: "constructor holds", phase: "constructor", http: true},
		{name: "initialize-only constructor holds", phase: "constructor", http: true, initializeOnly: true},
		{name: "preflight releases raft then holds", phase: "preflight", http: true},
		{name: "claim releases raft then holds", phase: "claim", http: true},
		{name: "constructor without HTTP exits", phase: "constructor"},
		{name: "preflight without HTTP exits", phase: "preflight"},
		{name: "claim without HTTP exits", phase: "claim"},
		{name: "non-PIN with HTTP exits", phase: "preflight", http: true, cause: nonPIN},
		{name: "cancellation during preflight exits cleanly", phase: "preflight", http: true, cancelOnError: true},
		{name: "hold respects deadline", phase: "constructor", http: true, deadline: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := healthTestConfig(t, "127.0.0.1:1")
			if !tc.http {
				cfg.HTTPAddr = ""
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.deadline {
				var cancelDeadline context.CancelFunc
				ctx, cancelDeadline = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer cancelDeadline()
			}
			cause := tc.cause
			if cause == nil {
				cause = backend.ErrPKCS11PINFailure
			}
			var contextStarts, opens atomic.Int32
			closed := make(chan struct{})
			var be *pinStartupBackend
			if tc.phase != "constructor" {
				software, err := backend.New(cfg.Backend)
				require.NoError(t, err)
				pub, err := software.PubKey()
				require.NoError(t, err)
				cfg.ExpectedPublicKey = base64.StdEncoding.EncodeToString(pub.Bytes())
				be = &pinStartupBackend{KeyBackend: software, phase: tc.phase, cause: cause,
					contextStarts: &contextStarts, closed: closed}
				if tc.cancelOnError {
					be.cancelOnError = cancel
				}
			}
			open := func(backend.Config) (backend.KeyBackend, error) {
				opens.Add(1)
				if contextStarts.Load() != 0 {
					return nil, errors.New("signal context started before context-free construction")
				}
				if tc.phase == "constructor" {
					close(closed)
					return nil, fmt.Errorf("construct backend: %w", cause)
				}
				return be, nil
			}
			startContext := func() (context.Context, context.CancelFunc) {
				contextStarts.Add(1)
				return ctx, func() {}
			}
			result := make(chan error, 1)
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				result <- runStart(cfg, tc.initializeOnly, io.Discard, open, startContext)
			}()
			t.Cleanup(func() {
				cancel()
				select {
				case <-finished:
				case <-time.After(10 * time.Second):
					t.Error("startup did not stop after cancellation")
				}
			})
			select {
			case <-closed:
			case <-time.After(20 * time.Second):
				t.Fatal("failed startup did not release the backend")
			}
			holds := tc.http && tc.cause == nil && !tc.cancelOnError && !tc.deadline
			if holds {
				select {
				case err := <-result:
					t.Fatalf("PIN failure exited instead of holding: %v", err)
				case <-time.After(150 * time.Millisecond):
				}
				code, _ := healthGet(cfg.HTTPAddr, "/livez")
				require.Equal(t, http.StatusOK, code)
				code, _ = healthGet(cfg.HTTPAddr, "/readyz")
				require.Equal(t, http.StatusServiceUnavailable, code)
				status, ok := healthStatus(t, cfg.HTTPAddr)
				require.True(t, ok)
				require.False(t, status.Ready)
				require.False(t, status.Raft.Leader)
				require.Empty(t, status.Nodes)
				if tc.phase == "constructor" {
					_, err := os.Stat(cfg.Raft.DataDir)
					require.ErrorIs(t, err, os.ErrNotExist)
				} else {
					require.Equal(t, "shutdown", status.Raft.State)
					ln, err := net.Listen("tcp", cfg.Raft.BindAddr)
					require.NoError(t, err, "parked replica must release its Raft listener")
					require.NoError(t, ln.Close())
				}
				cancel()
			}
			select {
			case err := <-result:
				switch {
				case holds || tc.cancelOnError:
					require.NoError(t, err)
				case tc.deadline:
					require.ErrorIs(t, err, context.DeadlineExceeded)
				default:
					require.ErrorIs(t, err, cause)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("startup did not return promptly")
			}
			require.EqualValues(t, 1, opens.Load(), "startup must never retry construction")
			if be != nil {
				require.EqualValues(t, 1, be.failedCalls.Load(), "startup must never retry the failed operation")
				require.Zero(t, be.signs.Load(), "failed startup must never sign consensus messages")
			}
			wantContexts := int32(1)
			if tc.phase == "constructor" && !tc.http {
				wantContexts = 0
			}
			require.Equal(t, wantContexts, contextStarts.Load(), "preflight and hold must share one context")
			if tc.http {
				require.Eventually(t, func() bool {
					code, _ := healthGet(cfg.HTTPAddr, "/livez")
					return code == 0
				}, 2*time.Second, 20*time.Millisecond, "HTTP endpoint must stop serving on exit")
			}
		})
	}
}
