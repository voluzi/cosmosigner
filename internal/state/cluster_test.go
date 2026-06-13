package state

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

// freeAddrs returns n distinct free 127.0.0.1 addresses for raft transports.
func freeAddrs(t *testing.T, n int) []string {
	t.Helper()
	addrs := make([]string, n)
	lns := make([]net.Listener, n)
	for i := range n {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		lns[i] = ln
		addrs[i] = ln.Addr().String()
	}
	for _, ln := range lns {
		_ = ln.Close()
	}
	return addrs
}

func waitLeader(t *testing.T, stores map[string]StateStore) string {
	t.Helper()
	var leaderID string
	require.Eventually(t, func() bool {
		count := 0
		for id, s := range stores {
			if s.IsLeader() {
				leaderID, count = id, count+1
			}
		}
		return count == 1
	}, 20*time.Second, 100*time.Millisecond, "no single raft leader emerged")
	return leaderID
}

func sig64() []byte {
	b := make([]byte, 64)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func newNode(t *testing.T, id, addr, dir string, bootstrap bool, members []Member) StateStore {
	t.Helper()
	s, err := NewRaftStore(RaftConfig{
		NodeID:       id,
		BindAddr:     addr,
		Advertise:    addr,
		DataDir:      dir,
		Bootstrap:    bootstrap,
		Members:      members,
		ApplyTimeout: 5 * time.Second,
	}, hclog.NewNullLogger())
	require.NoError(t, err)
	return s
}

// TestRaftCluster_BootstrapOneAndFailover verifies the recommended formation
// pattern (one node bootstraps the full member list, the others join bare),
// that the high-water-mark replicates, and that it survives leader failover.
func TestRaftCluster_BootstrapOneAndFailover(t *testing.T) {
	if testing.Short() {
		t.Skip("multi-node raft test")
	}
	addrs := freeAddrs(t, 3)
	ids := []string{"n0", "n1", "n2"}
	members := []Member{{ids[0], addrs[0]}, {ids[1], addrs[1]}, {ids[2], addrs[2]}}
	dir := t.TempDir()

	stores := map[string]StateStore{
		// n0 bootstraps with the full member list; n1/n2 start bare and the
		// leader pulls them in.
		ids[0]: newNode(t, ids[0], addrs[0], filepath.Join(dir, ids[0]), true, members),
		ids[1]: newNode(t, ids[1], addrs[1], filepath.Join(dir, ids[1]), false, nil),
		ids[2]: newNode(t, ids[2], addrs[2], filepath.Join(dir, ids[2]), false, nil),
	}
	defer func() {
		for _, s := range stores {
			_ = s.Close()
		}
	}()

	leaderID := waitLeader(t, stores)

	// Reserve + commit a sign on the leader.
	sb := voteSignBytes(100, 0, ts1, "A")
	res, err := stores[leaderID].Reserve(testChain, 100, 0, StepPrecommit, sb, ts1)
	require.NoError(t, err)
	require.False(t, res.Reuse)
	require.NoError(t, stores[leaderID].Commit(testChain, 100, 0, StepPrecommit, sb, sig64()))

	// A follower replicates the high-water-mark.
	var followerID string
	for id := range stores {
		if id != leaderID {
			followerID = id
			break
		}
	}
	require.Eventually(t, func() bool {
		st, err := stores[followerID].Get(testChain)
		return err == nil && st != nil && st.Height == 100
	}, 5*time.Second, 100*time.Millisecond, "follower did not replicate the high-water-mark")

	// Kill the leader; a survivor takes over (2 of 3 still has quorum).
	require.NoError(t, stores[leaderID].Close())
	delete(stores, leaderID)
	newLeaderID := waitLeader(t, stores)
	require.NotEqual(t, leaderID, newLeaderID)

	// State survived the failover: regression refused, advance allowed.
	_, err = stores[newLeaderID].Reserve(testChain, 99, 0, StepPrecommit, voteSignBytes(99, 0, ts1, "B"), ts1)
	require.ErrorIs(t, err, ErrRegression)
	res, err = stores[newLeaderID].Reserve(testChain, 101, 0, StepPrecommit, voteSignBytes(101, 0, ts1, "C"), ts1)
	require.NoError(t, err)
	require.False(t, res.Reuse)
}

// TestRaftCluster_BootstrapAllSymmetric verifies the symmetric alternative —
// every node bootstraps with the identical full member list — forms one cluster.
func TestRaftCluster_BootstrapAllSymmetric(t *testing.T) {
	if testing.Short() {
		t.Skip("multi-node raft test")
	}
	addrs := freeAddrs(t, 3)
	ids := []string{"m0", "m1", "m2"}
	members := []Member{{ids[0], addrs[0]}, {ids[1], addrs[1]}, {ids[2], addrs[2]}}
	dir := t.TempDir()

	stores := map[string]StateStore{}
	for i, id := range ids {
		stores[id] = newNode(t, id, addrs[i], filepath.Join(dir, id), true, members)
	}
	defer func() {
		for _, s := range stores {
			_ = s.Close()
		}
	}()

	leaderID := waitLeader(t, stores)
	sb := voteSignBytes(10, 0, ts1, "A")
	require.NoError(t, func() error { _, err := stores[leaderID].Reserve(testChain, 10, 0, StepPrecommit, sb, ts1); return err }())

	// Exactly one leader, three voters, replication works.
	require.Eventually(t, func() bool {
		for id := range stores {
			st, err := stores[id].Get(testChain)
			if err != nil || st == nil || st.Height != 10 {
				return false
			}
		}
		return true
	}, 5*time.Second, 100*time.Millisecond, "all members should converge on the high-water-mark")
}

// TestBootstrapServers_SelfMustBeMember guards the common misconfiguration.
func TestBootstrapServers_SelfMustBeMember(t *testing.T) {
	_, err := bootstrapServers(RaftConfig{
		NodeID:  "missing",
		Members: []Member{{ID: "a", Address: "1.2.3.4:1"}, {ID: "b", Address: "5.6.7.8:1"}},
	}, "missing", "9.9.9.9:1")
	require.ErrorContains(t, err, "not in the member list")
}
