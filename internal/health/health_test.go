package health

import (
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	cmtlog "github.com/cometbft/cometbft/libs/log"
	"github.com/stretchr/testify/require"
)

func startTestServer(t *testing.T) *Server {
	t.Helper()
	s, err := Start("127.0.0.1:0", Info{Version: "1.2.3", ChainID: "chain", RaftNodeID: "node-1"}, cmtlog.NewNopLogger())
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func get(t *testing.T, s *Server, path string) (int, string) {
	t.Helper()
	client := http.Client{Timeout: 5 * time.Second}
	res, err := client.Get("http://" + s.Addr() + path)
	require.NoError(t, err)
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return res.StatusCode, string(body)
}

func TestLivezDoesNotDependOnReadiness(t *testing.T) {
	s := startTestServer(t)

	code, body := get(t, s, "/livez")
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, "ok\n", body)

	s.SetReady(true)
	s.SetReady(false)
	code, _ = get(t, s, "/livez")
	require.Equal(t, http.StatusOK, code, "a replica that is no longer ready is still alive")
}

func TestReadyzFollowsSetReady(t *testing.T) {
	s := startTestServer(t)

	code, _ := get(t, s, "/readyz")
	require.Equal(t, http.StatusServiceUnavailable, code)

	s.SetReady(true)
	code, _ = get(t, s, "/readyz")
	require.Equal(t, http.StatusOK, code)

	s.SetReady(false)
	code, _ = get(t, s, "/readyz")
	require.Equal(t, http.StatusServiceUnavailable, code)
}

func TestStatusBeforeRaftIsOpen(t *testing.T) {
	s := startTestServer(t)

	code, body := get(t, s, "/status")
	require.Equal(t, http.StatusOK, code)
	require.JSONEq(t, `{
		"version": "1.2.3",
		"chain_id": "chain",
		"raft": {"node_id": "node-1", "state": "unknown", "leader": false},
		"ready": false,
		"nodes": []
	}`, body)
}

func TestStatusReportsRaftRoleAndNodes(t *testing.T) {
	s := startTestServer(t)
	s.SetReady(true)
	s.SetRaft(func() Raft { return Raft{State: "leader", Leader: true} })
	s.SetNodes(func() []Node {
		return []Node{
			{Address: "10.0.0.5:26659", Connected: true, LastActivity: time.Date(2026, time.October, 2, 12, 0, 0, 0, time.FixedZone("", 2*60*60))},
			{Address: "10.0.0.6:26659"},
		}
	})

	code, body := get(t, s, "/status")
	require.Equal(t, http.StatusOK, code)
	require.JSONEq(t, `{
		"version": "1.2.3",
		"chain_id": "chain",
		"raft": {"node_id": "node-1", "state": "leader", "leader": true},
		"ready": true,
		"nodes": [
			{"address": "10.0.0.5:26659", "connected": true, "last_activity": "2026-10-02T10:00:00Z"},
			{"address": "10.0.0.6:26659", "connected": false}
		]
	}`, body)
}

func TestEndpointsRejectWrites(t *testing.T) {
	s := startTestServer(t)
	client := http.Client{Timeout: 5 * time.Second}
	for _, path := range []string{"/livez", "/readyz", "/status"} {
		res, err := client.Post("http://"+s.Addr()+path, "text/plain", nil)
		require.NoError(t, err)
		require.NoError(t, res.Body.Close())
		require.Equal(t, http.StatusMethodNotAllowed, res.StatusCode, path)
	}
}

func TestStartFailsWhenTheAddressIsTaken(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	_, err = Start(ln.Addr().String(), Info{}, cmtlog.NewNopLogger())
	require.ErrorContains(t, err, "http_addr")
}

func TestDisabledServerIsANoOp(t *testing.T) {
	var s *Server
	s.SetReady(true)
	s.SetRaft(func() Raft { return Raft{} })
	s.SetNodes(func() []Node { return nil })
	require.Empty(t, s.Addr())
	require.NoError(t, s.Close())
}
