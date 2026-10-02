// Package health serves the operational HTTP endpoints: /livez, /readyz and /status. They carry no
// authentication, so /status reports only what the logs already print: no key material, backend
// coordinates, credentials, or raft peer addresses.
package health

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	cmtlog "github.com/cometbft/cometbft/libs/log"
)

// Info is the static part of /status, known before the backend or raft are opened.
type Info struct {
	Version    string
	ChainID    string
	RaftNodeID string
}

// Raft is this replica's raft role.
type Raft struct {
	State  string
	Leader bool
}

// Node is one target node connection held by this replica.
type Node struct {
	Address   string
	Connected bool
	// LastActivity is the last request handled on the connection; zero while not connected.
	LastActivity time.Time
}

type statusResponse struct {
	Version string       `json:"version"`
	ChainID string       `json:"chain_id"`
	Raft    raftResponse `json:"raft"`
	Ready   bool         `json:"ready"`
	Nodes   []nodeStatus `json:"nodes"`
}

type raftResponse struct {
	NodeID string `json:"node_id"`
	State  string `json:"state"`
	Leader bool   `json:"leader"`
}

type nodeStatus struct {
	Address      string     `json:"address"`
	Connected    bool       `json:"connected"`
	LastActivity *time.Time `json:"last_activity,omitempty"`
}

// Server serves the health endpoints. A nil *Server is valid and does nothing, which is how a
// disabled listener is represented.
type Server struct {
	info   Info
	logger cmtlog.Logger
	ln     net.Listener
	http   *http.Server

	ready atomic.Bool
	raft  atomic.Pointer[func() Raft]
	nodes atomic.Pointer[func() []Node]
}

// Start binds addr and serves in the background. The bind happens before Start returns, so a port
// that cannot be opened is reported to the caller instead of leaving probes to fail later.
func Start(addr string, info Info, logger cmtlog.Logger) (*Server, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen on http_addr %q: %w", addr, err)
	}
	s := &Server{info: info, logger: logger, ln: ln}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /livez", s.livez)
	mux.HandleFunc("GET /readyz", s.readyz)
	mux.HandleFunc("GET /status", s.status)
	s.http = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       time.Minute,
	}
	go func() {
		if err := s.http.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("health endpoints stopped", "err", err)
		}
	}()
	logger.Info("health endpoints listening", "addr", ln.Addr().String())
	return s, nil
}

// Addr returns the bound address, which differs from the configured one when the port was 0.
func (s *Server) Addr() string {
	if s == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// SetReady sets what /readyz answers.
func (s *Server) SetReady(ready bool) {
	if s != nil {
		s.ready.Store(ready)
	}
}

// SetRaft supplies the raft role for /status. fn is called on every request and must not block.
func (s *Server) SetRaft(fn func() Raft) {
	if s != nil {
		s.raft.Store(&fn)
	}
}

// SetNodes supplies the served nodes for /status. fn is called on every request and must not block.
func (s *Server) SetNodes(fn func() []Node) {
	if s != nil {
		s.nodes.Store(&fn)
	}
}

// Close stops serving.
func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	return s.http.Close()
}

// livez answers from the HTTP server alone. It must stay independent of the key backend and of
// raft quorum: restarting a replica cannot repair either, and restarting all of them over a shared
// outage would take down a signer that recovers by itself.
func (s *Server) livez(w http.ResponseWriter, _ *http.Request) {
	writeText(w, http.StatusOK, "ok")
}

func (s *Server) readyz(w http.ResponseWriter, _ *http.Request) {
	if !s.ready.Load() {
		writeText(w, http.StatusServiceUnavailable, "not ready")
		return
	}
	writeText(w, http.StatusOK, "ok")
}

func (s *Server) status(w http.ResponseWriter, _ *http.Request) {
	res := statusResponse{
		Version: s.info.Version,
		ChainID: s.info.ChainID,
		Raft:    raftResponse{NodeID: s.info.RaftNodeID, State: "unknown"},
		Ready:   s.ready.Load(),
		Nodes:   []nodeStatus{},
	}
	if fn := s.raft.Load(); fn != nil {
		raft := (*fn)()
		res.Raft.State, res.Raft.Leader = raft.State, raft.Leader
	}
	if fn := s.nodes.Load(); fn != nil {
		for _, node := range (*fn)() {
			entry := nodeStatus{Address: node.Address, Connected: node.Connected}
			if !node.LastActivity.IsZero() {
				at := node.LastActivity.UTC()
				entry.LastActivity = &at
			}
			res.Nodes = append(res.Nodes, entry)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(res); err != nil {
		s.logger.Debug("write status response", "err", err)
	}
}

func writeText(w http.ResponseWriter, code int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(code)
	_, _ = fmt.Fprintln(w, body)
}
