package state

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

// TestResolveAdvertiseSucceedsImmediately verifies the common path pays no retry delay.
func TestResolveAdvertiseSucceedsImmediately(t *testing.T) {
	start := time.Now()
	addr, err := resolveAdvertise(context.Background(), "127.0.0.1:7070", hclog.NewNullLogger())
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1:7070", addr.String())
	require.Less(t, time.Since(start), advertiseResolveInterval)
}

// TestResolveAdvertiseReturnsAdvertisableTCPAddr pins the contract raft depends on: the plain-TCP
// transport rejects a non-TCP or unspecified advertise address, so resolution must yield a concrete
// *net.TCPAddr before the transport is built.
func TestResolveAdvertiseReturnsAdvertisableTCPAddr(t *testing.T) {
	addr, err := resolveAdvertise(context.Background(), "localhost:7070", hclog.NewNullLogger())
	require.NoError(t, err)
	require.IsType(t, &net.TCPAddr{}, addr)
	require.False(t, addr.IP.IsUnspecified(), "advertise address must not be unspecified")
	require.Equal(t, 7070, addr.Port)
}

// TestResolveAdvertiseAcceptsIPLiterals verifies IP literals resolve without any DNS lookup, and
// that an IPv6 zone survives. net.ParseIP rejects a zoned literal like "fe80::1%eth0", so a naive
// literal check sends link-local addresses to DNS, where they never resolve.
func TestResolveAdvertiseAcceptsIPLiterals(t *testing.T) {
	// A budget so short that any DNS fallback would fail the assertions below.
	restoreBudget(t, 50*time.Millisecond, 10*time.Millisecond)

	for _, tc := range []struct {
		name      string
		advertise string
		wantIP    string
		wantZone  string
	}{
		{"ipv4", "10.0.0.5:7070", "10.0.0.5", ""},
		{"ipv6", "[fd00::1]:7070", "fd00::1", ""},
		{"ipv6 link-local with zone", "[fe80::1%eth0]:7070", "fe80::1", "eth0"},
		{"ipv6 with empty zone", "[fe80::1%]:7070", "fe80::1", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, err := resolveAdvertise(context.Background(), tc.advertise, hclog.NewNullLogger())
			require.NoError(t, err)
			require.Equal(t, tc.wantIP, addr.IP.String())
			require.Equal(t, tc.wantZone, addr.Zone)
			require.Equal(t, 7070, addr.Port)
		})
	}
}

// TestResolveAdvertiseRejectsMalformedImmediately verifies a permanent syntax error is not retried.
// Retrying one would turn an operator typo into a full-budget hang instead of an immediate failure.
func TestResolveAdvertiseRejectsMalformedImmediately(t *testing.T) {
	// Shrink the budget so a regression (retrying these) shows up quickly rather than stalling the
	// suite for 90s.
	restoreBudget(t, 2*time.Second, 100*time.Millisecond)

	for _, tc := range []struct {
		name      string
		advertise string
		wantErr   string
	}{
		{"missing port", "signer-0.signer.ns.svc", "parse advertise address"},
		{"non-numeric port", "signer-0.signer.ns.svc:http-alt-typo", "parse advertise port"},
		{"empty host", ":7070", "has no host"},
		{"zone on IPv4 literal", "127.0.0.1%eth0:7070", "zones apply to IPv6 only"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			_, err := resolveAdvertise(context.Background(), tc.advertise, hclog.NewNullLogger())
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.wantErr)
			// A single (possibly slow) parse attempt is fine; consuming the retry budget is not.
			// The port case does a real service-name lookup, so allow for one of those.
			require.Less(t, time.Since(start), advertiseResolveTimeout,
				"a permanently malformed address must fail without exhausting the retry budget")
		})
	}
}

// TestResolveAdvertiseDoesNotPreRejectHostnames documents a deliberate choice: hostname spelling is
// not used as a resolvability test. A DNS label may legally contain bytes RFC 1123 forbids
// (underscores appear in real deployments), and the Go resolver returns the same "no such host" for
// a typo as for a record that has not been published yet. Pre-rejecting on syntax would therefore
// fail startups that work today, so these names must reach the resolver and fail on the budget.
func TestResolveAdvertiseDoesNotPreRejectHostnames(t *testing.T) {
	restoreBudget(t, 200*time.Millisecond, 50*time.Millisecond)

	for _, advertise := range []string{
		"foo_bar.invalid:7070",  // underscore
		"-foo.invalid:7070",     // leading hyphen
		"foo-.invalid:7070",     // trailing hyphen
		"foo..bar.invalid:7070", // empty label
	} {
		t.Run(advertise, func(t *testing.T) {
			_, err := resolveAdvertise(context.Background(), advertise, hclog.NewNullLogger())
			require.Error(t, err, "the name still does not resolve")
			require.Contains(t, err.Error(), "resolve advertise address",
				"must fail as an unresolved lookup, not be pre-rejected as malformed")
		})
	}
}

// TestResolveAdvertiseFailsAfterBudget verifies the retry stays bounded: an unresolvable hostname
// must still fail the process rather than hang invisibly past the startup probe.
func TestResolveAdvertiseFailsAfterBudget(t *testing.T) {
	restoreBudget(t, 300*time.Millisecond, 50*time.Millisecond)

	// Syntactically valid, permanently unresolvable (RFC 6761 reserves .invalid).
	bad := fmt.Sprintf("no-such-host-%d.invalid:7070", time.Now().UnixNano())
	start := time.Now()
	_, err := resolveAdvertise(context.Background(), bad, hclog.NewNullLogger())
	require.Error(t, err)
	require.Contains(t, err.Error(), "resolve advertise address")
	require.Less(t, time.Since(start), 10*time.Second, "retry must be bounded")
}

// TestResolveAdvertiseHonoursCallerContext verifies a cancelled caller context aborts the wait, so
// a stalled resolver cannot outlive shutdown.
func TestResolveAdvertiseHonoursCallerContext(t *testing.T) {
	restoreBudget(t, 90*time.Second, 50*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	bad := fmt.Sprintf("no-such-host-%d.invalid:7070", time.Now().UnixNano())
	start := time.Now()
	_, err := resolveAdvertise(ctx, bad, hclog.NewNullLogger())
	require.Error(t, err)
	// Returned on the caller's deadline, far short of the 90s budget.
	require.Less(t, time.Since(start), 10*time.Second)
}

func restoreBudget(t *testing.T, timeout, interval time.Duration) {
	t.Helper()
	origTimeout, origInterval := advertiseResolveTimeout, advertiseResolveInterval
	advertiseResolveTimeout, advertiseResolveInterval = timeout, interval
	t.Cleanup(func() {
		advertiseResolveTimeout, advertiseResolveInterval = origTimeout, origInterval
	})
}
