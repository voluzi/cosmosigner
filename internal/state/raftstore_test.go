package state

import (
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
	addr, err := resolveAdvertise("127.0.0.1:7070", hclog.NewNullLogger())
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1:7070", addr.String())
	require.Less(t, time.Since(start), advertiseResolveInterval)
}

// TestResolveAdvertiseReturnsAdvertisableTCPAddr pins the contract raft depends on: the plain-TCP
// transport rejects a non-TCP or unspecified advertise address, so resolution must yield a concrete
// *net.TCPAddr before the transport is built.
func TestResolveAdvertiseReturnsAdvertisableTCPAddr(t *testing.T) {
	addr, err := resolveAdvertise("localhost:7070", hclog.NewNullLogger())
	require.NoError(t, err)
	require.IsType(t, &net.TCPAddr{}, addr)
	require.False(t, addr.IP.IsUnspecified(), "advertise address must not be unspecified")
	require.Equal(t, 7070, addr.Port)
}

// TestResolveAdvertiseFailsAfterBudget verifies the retry stays bounded: a genuinely wrong address
// must still fail the process rather than hang invisibly past the startup probe.
func TestResolveAdvertiseFailsAfterBudget(t *testing.T) {
	// Shrink the budget for the test rather than waiting out the real one.
	origTimeout, origInterval := advertiseResolveTimeout, advertiseResolveInterval
	advertiseResolveTimeout, advertiseResolveInterval = 150*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() {
		advertiseResolveTimeout, advertiseResolveInterval = origTimeout, origInterval
	})

	// A syntactically valid but unresolvable name.
	bad := fmt.Sprintf("no-such-host-%d.invalid:7070", time.Now().UnixNano())
	start := time.Now()
	_, err := resolveAdvertise(bad, hclog.NewNullLogger())
	require.Error(t, err)
	require.Contains(t, err.Error(), "resolve advertise address")
	// Bounded: it gave up rather than retrying forever.
	require.Less(t, time.Since(start), 5*time.Second)
}
