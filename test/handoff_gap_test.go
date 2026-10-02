package test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cometbft/cometbft/crypto/ed25519"
	cmtlog "github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/privval"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"

	"github.com/voluzi/cosmosigner/internal/backend"
	"github.com/voluzi/cosmosigner/internal/server"
	"github.com/voluzi/cosmosigner/internal/signer"
	"github.com/voluzi/cosmosigner/internal/state"
)

// podLink is one signer pod's network path to the node's privval listener. It models what the
// node's kernel sees of a pod that closed its socket and then exited.
//
// On loopback the closing side's kernel outlives the process, so any later write from the node is
// answered with a reset and the node notices at once. A deleted pod is different: its close reaches
// the node as a FIN, the process exits, and shortly after that the pod's network is gone, so later
// writes from the node are answered by nobody. liveFor is how long after the process exits a write
// from the node on a closed connection still gets a reset; past it, writes are swallowed. A negative
// liveFor never stops answering, which is plain loopback behaviour.
//
// A reset sent by the signer itself is forwarded as a reset: it is on the wire before the process
// exits, so no model of the pod's lifetime applies to it.
type podLink struct {
	ln      net.Listener
	target  string
	liveFor time.Duration
	wg      sync.WaitGroup

	mu       sync.Mutex
	exitedAt time.Time  // zero while the signer process runs
	conns    []net.Conn // every proxied socket, closed at cleanup
}

func (p *podLink) own(c net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.conns = append(p.conns, c)
}

// exit marks the signer process as gone; its pod's network follows liveFor later.
func (p *podLink) exit() {
	p.mu.Lock()
	p.exitedAt = time.Now()
	p.mu.Unlock()
}

// gone reports whether nothing answers for the pod any more.
func (p *podLink) gone() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.liveFor >= 0 && !p.exitedAt.IsZero() && time.Since(p.exitedAt) >= p.liveFor
}

func newPodLink(t *testing.T, target string, liveFor time.Duration) *podLink {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	p := &podLink{ln: ln, target: target, liveFor: liveFor}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			p.wg.Add(1)
			go func() {
				defer p.wg.Done()
				p.pipe(c.(*net.TCPConn))
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		// Links are cleaned up before the lifecycles are stopped, so a replica may still hold a live
		// connection through this one; close it rather than wait for the replica.
		p.mu.Lock()
		for _, c := range p.conns {
			_ = c.Close()
		}
		p.mu.Unlock()
		p.wg.Wait()
	})
	return p
}

func (p *podLink) addr() string { return p.ln.Addr().String() }

func reset(c *net.TCPConn) {
	_ = c.SetLinger(0)
	_ = c.Close()
}

func (p *podLink) pipe(signerSide *net.TCPConn) {
	p.own(signerSide)
	raw, err := net.Dial("tcp", p.target)
	if err != nil {
		reset(signerSide)
		return
	}
	nodeSide := raw.(*net.TCPConn)
	p.own(nodeSide)

	var signerClosed atomic.Bool // the signer's FIN arrived

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, err := nodeSide.Read(buf)
			if err != nil {
				_ = signerSide.Close()
				_ = nodeSide.Close()
				return
			}
			switch {
			case !signerClosed.Load():
				_, _ = signerSide.Write(buf[:n])
			case !p.gone():
				// The pod's kernel is still there and answers data for a closed socket with a reset.
				reset(nodeSide)
				return
			default:
				// The pod is gone: the node's write is answered by nobody.
			}
		}
	}()

	_, err = io.Copy(nodeSide, signerSide)
	if err != nil {
		// Anything but a clean end of stream: the signer reset the connection (or the node went
		// away, in which case this reset is a no-op).
		reset(nodeSide)
		_ = signerSide.Close()
	} else {
		signerClosed.Store(true)
		_ = nodeSide.CloseWrite()
		_ = signerSide.Close()
	}
	// Bound the swallow phase so a link never outlives the test by more than the node's own timeouts.
	_ = nodeSide.SetReadDeadline(time.Now().Add(30 * time.Second))
	<-done
}

// slowBackend adds a fixed latency to every signature, standing in for a remote KMS.
type slowBackend struct {
	backend.KeyBackend
	latency time.Duration
}

func (b *slowBackend) Sign(signBytes []byte) ([]byte, error) {
	time.Sleep(b.latency)
	return b.KeyBackend.Sign(signBytes)
}

// nodeLog records the node-side privval endpoint's log lines with their time, so a handoff can be
// laid out as a timeline next to the signatures.
type nodeLog struct {
	mu    sync.Mutex
	lines []nodeLogLine
}

type nodeLogLine struct {
	at  time.Time
	msg string
}

func (l *nodeLog) add(msg string, keyvals []interface{}) {
	if len(keyvals) > 0 {
		msg += " " + fmt.Sprint(keyvals...)
	}
	l.mu.Lock()
	l.lines = append(l.lines, nodeLogLine{at: time.Now(), msg: msg})
	l.mu.Unlock()
}

func (l *nodeLog) Debug(string, ...interface{})        {}
func (l *nodeLog) Info(msg string, kv ...interface{})  { l.add(msg, kv) }
func (l *nodeLog) Error(msg string, kv ...interface{}) { l.add(msg, kv) }
func (l *nodeLog) With(...interface{}) cmtlog.Logger   { return l }
func (l *nodeLog) between(from, to time.Time) []nodeLogLine {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []nodeLogLine
	for _, line := range l.lines {
		if !line.at.Before(from) && !line.at.After(to) {
			out = append(out, line)
		}
	}
	return out
}

type signEvent struct {
	height     int64
	start, end time.Time
	err        error
}

type handoffRigConfig struct {
	// liveFor is the podLink setting; see podLink.
	liveFor     time.Duration
	signLatency time.Duration
}

// handoffRig is a three-replica signer in front of a node that behaves like a real one: a
// SignerListenerEndpoint with cometbft's default timeouts and its ping routine running, behind the
// same RetrySignerClient node/setup.go builds. Unlike clusterHarness, a replica whose lifecycle was
// shut down can be started again, so one rig serves any number of handoffs.
type handoffRig struct {
	t      *testing.T
	stores []state.StateStore
	client *privval.RetrySignerClient
	log    *nodeLog

	start   func(i int)
	cancels []context.CancelFunc
	done    []chan struct{}

	mu     sync.Mutex
	events []signEvent
}

func newHandoffRig(t *testing.T, cfg handoffRigConfig) *handoffRig {
	t.Helper()
	if testing.Short() {
		t.Skip("multi-node raft test")
	}
	var be backend.KeyBackend = backend.NewSoftwareFromPriv(ed25519.GenPrivKey())
	if cfg.signLatency > 0 {
		be = &slowBackend{KeyBackend: be, latency: cfg.signLatency}
	}
	r := &handoffRig{t: t, log: &nodeLog{}}
	members := []state.Member{
		{ID: "n0", Address: freeAddr(t)},
		{ID: "n1", Address: freeAddr(t)},
		{ID: "n2", Address: freeAddr(t)},
	}
	for i, member := range members {
		store, err := state.NewRaftStore(state.RaftConfig{
			NodeID: member.ID, BindAddr: member.Address, DataDir: t.TempDir(),
			Bootstrap: i == 0, Insecure: true, Members: members,
		}, hclog.NewNullLogger())
		require.NoError(t, err)
		r.stores = append(r.stores, store)
		t.Cleanup(func() { require.NoError(t, store.Close()) })
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	// No timeout options: the node runs the endpoint with cometbft's defaults, and the ping interval
	// derived from them is what bounds the stall under study.
	sl := privval.NewSignerListenerEndpoint(r.log, privval.NewTCPListener(ln, ed25519.GenPrivKey()))
	require.NoError(t, sl.Start())
	t.Cleanup(func() { _ = sl.Stop() })
	r.cancels = make([]context.CancelFunc, len(r.stores))
	r.done = make([]chan struct{}, len(r.stores))
	r.start = func(i int) {
		// A fresh link per start: a restarted replica is a new pod.
		link := newPodLink(t, ln.Addr().String(), cfg.liveFor)
		pv, err := signer.New(be, r.stores[i])
		require.NoError(t, err)
		lc := server.New(server.Config{ChainID: itestChain}, server.StaticNodes{link.addr()}, pv,
			ed25519.GenPrivKey(), r.stores[i], cmtlog.NewNopLogger())
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		r.cancels[i], r.done[i] = cancel, done
		go func() {
			defer close(done)
			_ = lc.Run(ctx)
			link.exit()
		}()
	}
	t.Cleanup(func() {
		for i := range r.stores {
			r.cancels[i]()
		}
		for i := range r.stores {
			select {
			case <-r.done[i]:
			case <-time.After(15 * time.Second):
				t.Error("signer lifecycle did not stop")
			}
		}
	})
	for i := range r.stores {
		r.start(i)
	}

	sc, err := privval.NewSignerClient(sl, itestChain)
	require.NoError(t, err)
	// The retry policy of cometbft's node/setup.go.
	r.client = privval.NewRetrySignerClient(sc, 50, 100*time.Millisecond)
	return r
}

func (r *handoffRig) leader() int {
	leader := -1
	require.Eventually(r.t, func() bool {
		leader = -1
		for i, store := range r.stores {
			if store.IsLeader() {
				if leader != -1 {
					return false
				}
				leader = i
			}
		}
		return leader != -1
	}, 15*time.Second, 5*time.Millisecond, "no single raft leader")
	return leader
}

// sign signs one vote at height and records it.
func (r *handoffRig) sign(height int64) signEvent {
	ev := signEvent{height: height, start: time.Now()}
	ev.err = r.client.SignVote(itestChain, makeVote(height, 0, ev.start.UTC(), "block-"+strconv.FormatInt(height, 10)))
	ev.end = time.Now()
	r.mu.Lock()
	r.events = append(r.events, ev)
	r.mu.Unlock()
	return ev
}

// signAtCadence signs consecutive heights, one every cadence, until ctx ends. A signature that takes
// longer than the cadence delays the next one instead of piling up, as consensus does.
func (r *handoffRig) signAtCadence(ctx context.Context, from int64, cadence time.Duration) {
	next := time.Now()
	for height := from; ; height++ {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Until(next)):
		}
		r.sign(height)
		next = next.Add(cadence)
		if now := time.Now(); next.Before(now) {
			next = now
		}
	}
}

// handOff shuts the current leader's lifecycle down gracefully, as SIGTERM does, starts it again as
// the restarted pod would, and returns when the shutdown began and when it completed.
func (r *handoffRig) handOff() (began, retired time.Time) {
	leader := r.leader()
	began = time.Now()
	r.cancels[leader]()
	select {
	case <-r.done[leader]:
	case <-time.After(15 * time.Second):
		r.t.Fatal("leader lifecycle did not stop")
	}
	retired = time.Now()
	require.False(r.t, r.stores[leader].IsLeader())
	r.start(leader)
	return began, retired
}

func (r *handoffRig) snapshot() []signEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]signEvent(nil), r.events...)
}

// successAfter reports whether a signature that started after t has succeeded.
func (r *handoffRig) successAfter(t time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.events) - 1; i >= 0; i-- {
		if ev := r.events[i]; ev.err == nil && ev.start.After(t) {
			return true
		}
	}
	return false
}

func classifySignError(err error) string {
	var remote *privval.RemoteSignerError
	switch {
	case errors.As(err, &remote):
		return "RemoteSignerError: " + remote.Description
	case strings.Contains(err.Error(), "exhausted all attempts"):
		return "retries exhausted: " + err.Error()
	default:
		return fmt.Sprintf("%T: %v", err, err)
	}
}

// TestIntegration_GracefulLeaderShutdownResetsNodeConnection pins the property the node depends on
// when the outgoing leader's pod is gone by the time the node next writes: the node must learn from
// the close itself that the connection is dead. A FIN does not tell it — cometbft keeps a connection
// whose reads return EOF, and with nobody left to reset its writes it retries on that connection
// until its own ping fails, a ping interval (3.3s by default) after the last answer.
func TestIntegration_GracefulLeaderShutdownResetsNodeConnection(t *testing.T) {
	// liveFor 0: the pod's network goes with the process, so nothing answers the node after the close.
	r := newHandoffRig(t, handoffRigConfig{liveFor: 0})
	require.Eventually(t, func() bool { return r.sign(1).err == nil }, 30*time.Second, 100*time.Millisecond)

	height := int64(2)
	for range 3 {
		_, retired := r.handOff()
		// Past any plausible lifetime of the pod's network, and well inside the ping interval, so
		// only the close itself can have told the node.
		time.Sleep(300 * time.Millisecond)
		ev := r.sign(height)
		height++
		if ev.err != nil {
			for _, l := range r.log.between(retired.Add(-5*time.Second), time.Now()) {
				t.Logf("  %+10.4fs  node: %s", l.at.Sub(retired).Seconds(), l.msg)
			}
		}
		require.NoError(t, ev.err)
		require.Less(t, ev.end.Sub(retired), 1500*time.Millisecond,
			"the node waited for its ping to notice that the outgoing leader's connection was closed")
	}
}

// TestIntegration_GracefulLeaderShutdownNeverRefusesNode pins that a node never hears a refusal from
// a leader that is shutting down. cometbft does not retry a remote signer error, so a refusal is a
// lost vote, where a dropped connection is retried onto the next leader.
//
// A request has to fall inside the handoff for a refusal to be possible at all, which at one request
// per 1.4s block happens in a fraction of handoffs. Signing every 100ms puts one inside every
// handoff, so a few handoffs are enough to tell the two orders apart.
func TestIntegration_GracefulLeaderShutdownNeverRefusesNode(t *testing.T) {
	r := newHandoffRig(t, handoffRigConfig{liveFor: 0})
	require.Eventually(t, func() bool { return r.sign(1).err == nil }, 30*time.Second, 100*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	signing := make(chan struct{})
	go func() {
		defer close(signing)
		r.signAtCadence(ctx, 2, 100*time.Millisecond)
	}()
	stop := func() {
		cancel()
		<-signing
	}
	defer stop()

	for range 5 {
		// Long enough for the replica restarted by the previous handoff to rejoin as a follower.
		time.Sleep(300 * time.Millisecond)
		_, retired := r.handOff()
		require.Eventually(t, func() bool { return r.successAfter(retired) }, 10*time.Second, time.Millisecond,
			"signing did not resume after the handoff")
	}
	stop()

	events := r.snapshot()
	require.NotEmpty(t, events)
	for _, ev := range events {
		if ev.err != nil {
			t.Errorf("height %d was not signed: %s", ev.height, classifySignError(ev.err))
		}
	}
}

// TestIntegration_HandoffGapStudy measures what a node loses across many graceful leader shutdowns.
// It is a measurement, not a check, so it only runs on request:
//
//	HANDOFF_STUDY=100 go test ./test -run HandoffGapStudy -v -timeout 2h
//
// HANDOFF_STUDY is the number of handoffs per configuration; HANDOFF_STUDY_ONLY, if set, is a
// substring filter on the configuration name.
func TestIntegration_HandoffGapStudy(t *testing.T) {
	handoffs, _ := strconv.Atoi(os.Getenv("HANDOFF_STUDY"))
	if handoffs <= 0 {
		t.Skip("set HANDOFF_STUDY=<handoffs per configuration> to run")
	}
	only := os.Getenv("HANDOFF_STUDY_ONLY")
	links := []struct {
		name    string
		liveFor time.Duration
	}{
		{"loopback", -1},
		{"pod-gone-after-300ms", 300 * time.Millisecond},
		{"pod-gone-at-once", 0},
	}
	for _, link := range links {
		for _, latency := range []time.Duration{0, 150 * time.Millisecond} {
			for _, cadence := range []time.Duration{100 * time.Millisecond, 500 * time.Millisecond, 1400 * time.Millisecond} {
				name := fmt.Sprintf("%s/sign=%s/cadence=%s", link.name, latency, cadence)
				if !strings.Contains(name, only) {
					continue
				}
				t.Run(name, func(t *testing.T) {
					t.Parallel()
					runHandoffStudy(t, handoffRigConfig{liveFor: link.liveFor, signLatency: latency}, cadence, handoffs)
				})
			}
		}
	}
}

func runHandoffStudy(t *testing.T, cfg handoffRigConfig, cadence time.Duration, handoffs int) {
	r := newHandoffRig(t, cfg)
	require.Eventually(t, func() bool { return r.sign(1).err == nil }, 30*time.Second, 100*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	signing := make(chan struct{})
	go func() {
		defer close(signing)
		r.signAtCadence(ctx, 2, cadence)
	}()
	defer func() {
		cancel()
		<-signing
	}()

	type window struct{ began, retired, settled time.Time }
	var windows []window
	rng := rand.New(rand.NewSource(1))
	for range handoffs {
		// A random phase against the signing cadence, after a quiet stretch that lets the restarted
		// replica rejoin and the node's ping timer reflect steady state.
		time.Sleep(2*cadence + time.Duration(rng.Int63n(int64(cadence))))
		began, retired := r.handOff()
		require.Eventually(t, func() bool { return r.successAfter(retired) }, 30*time.Second, time.Millisecond)
		windows = append(windows, window{began: began, retired: retired, settled: time.Now()})
	}
	cancel()
	<-signing

	events := r.snapshot()
	gaps := make([]time.Duration, 0, len(windows))
	errs := map[string]int{}
	worst, worstGap := 0, time.Duration(0)
	for i, w := range windows {
		// The gap of a handoff is the longest stretch without a new signature around it: from the
		// last success before the shutdown began to the first success that started after it ended.
		var last time.Time
		var gap time.Duration
		for _, ev := range events {
			if ev.end.Before(w.began.Add(-2*cadence)) || ev.start.After(w.settled) {
				continue
			}
			if ev.err != nil {
				errs[classifySignError(ev.err)]++
				continue
			}
			if !last.IsZero() && ev.end.Sub(last) > gap {
				gap = ev.end.Sub(last)
			}
			last = ev.end
		}
		gaps = append(gaps, gap)
		if gap > worstGap {
			worst, worstGap = i, gap
		}
	}

	sorted := append([]time.Duration(nil), gaps...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	pct := func(p float64) time.Duration { return sorted[int(p*float64(len(sorted)-1))].Round(time.Millisecond) }
	over := func(d time.Duration) int {
		n := 0
		for _, g := range gaps {
			if g > d {
				n++
			}
		}
		return n
	}
	t.Logf("handoffs=%d gap between consecutive signatures: p50=%s p90=%s p99=%s max=%s | over cadence+1s: %d, over cadence+2s: %d",
		len(gaps), pct(0.5), pct(0.9), pct(0.99), pct(1), over(cadence+time.Second), over(cadence+2*time.Second))
	// How long the shutdown took from SIGTERM to retirement, and how far the last sign request
	// before it lay from its start: a shutdown that waits for the node's next request shows up as
	// a long duration ending right after a request.
	durs := make([]time.Duration, 0, len(windows))
	for _, w := range windows {
		durs = append(durs, w.retired.Sub(w.began))
	}
	sort.Slice(durs, func(i, j int) bool { return durs[i] < durs[j] })
	t.Logf("shutdown duration (cancel to retired): p50=%s p90=%s max=%s, over 300ms: %d",
		durs[len(durs)/2].Round(time.Millisecond), durs[len(durs)*9/10].Round(time.Millisecond),
		durs[len(durs)-1].Round(time.Millisecond), len(durs)-sort.Search(len(durs), func(i int) bool { return durs[i] > 300*time.Millisecond }))
	if len(errs) == 0 {
		t.Logf("sign errors: none")
	}
	for class, n := range errs {
		t.Logf("sign error x%d: %s", n, class)
	}

	w := windows[worst]
	t.Logf("worst handoff (#%d, gap %s), times relative to the outgoing leader's retirement:", worst, worstGap.Round(time.Millisecond))
	type line struct {
		at  time.Time
		msg string
	}
	lines := []line{{w.began, "signer: graceful shutdown begins (leadership transfer)"}, {w.retired, "signer: outgoing leader retired its node connection and stopped"}}
	for _, l := range r.log.between(w.began.Add(-2*cadence), w.settled) {
		lines = append(lines, line{l.at, "node: " + l.msg})
	}
	for _, ev := range events {
		if ev.end.Before(w.began.Add(-2*cadence)) || ev.start.After(w.settled) {
			continue
		}
		outcome := "ok"
		if ev.err != nil {
			outcome = classifySignError(ev.err)
		}
		lines = append(lines, line{ev.start, fmt.Sprintf("node: sign h=%d requested", ev.height)})
		lines = append(lines, line{ev.end, fmt.Sprintf("node: sign h=%d returned after %s: %s", ev.height, ev.end.Sub(ev.start).Round(100*time.Microsecond), outcome)})
	}
	sort.SliceStable(lines, func(i, j int) bool { return lines[i].at.Before(lines[j].at) })
	for _, l := range lines {
		t.Logf("  %+10.4fs  %s", l.at.Sub(w.retired).Seconds(), l.msg)
	}
}
