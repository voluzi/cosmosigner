package server

import (
	"context"
	"fmt"
	"net"
	"sort"
	"time"
)

// NodeSource yields the current set of target node privval addresses to dial.
// Implementations may be static or dynamic (e.g. resolving a headless service).
type NodeSource interface {
	// Nodes returns the current target addresses. A returned error means the
	// set is unknown right now; callers keep their existing connections.
	Nodes() ([]string, error)
	// Describe returns a short human-readable description for logs.
	Describe() string
}

// StaticNodes is a fixed address list (non-k8s / explicit deployments).
type StaticNodes []string

func (s StaticNodes) Nodes() ([]string, error) { return []string(s), nil }
func (s StaticNodes) Describe() string         { return fmt.Sprintf("static%v", []string(s)) }

// HeadlessServiceNodes resolves a Kubernetes headless service's DNS A-records
// to per-pod addresses, dialing each pod on a fixed privval port.
//
// The service MUST set publishNotReadyAddresses: true so that nodes appear in
// DNS (and get a signer connection) while they are still starting up or syncing
// — a node with priv_validator_laddr set blocks at startup until a signer dials
// in, so gating discovery on readiness would deadlock it.
type HeadlessServiceNodes struct {
	host     string
	port     string
	resolver *net.Resolver
}

// NewHeadlessServiceNodes parses a host:port (the headless service FQDN and the
// nodes' shared privval port).
func NewHeadlessServiceNodes(hostPort string) (*HeadlessServiceNodes, error) {
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return nil, fmt.Errorf("invalid node-service %q (want host:port): %w", hostPort, err)
	}
	if host == "" || port == "" {
		return nil, fmt.Errorf("invalid node-service %q (want host:port)", hostPort)
	}
	return &HeadlessServiceNodes{host: host, port: port, resolver: net.DefaultResolver}, nil
}

func (h *HeadlessServiceNodes) Nodes() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := h.resolver.LookupHost(ctx, h.host)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", h.host, err)
	}
	addrs := make([]string, 0, len(ips))
	for _, ip := range ips {
		addrs = append(addrs, net.JoinHostPort(ip, h.port))
	}
	sort.Strings(addrs) // stable ordering for deterministic logs/diffs
	return addrs, nil
}

func (h *HeadlessServiceNodes) Describe() string {
	return fmt.Sprintf("headless-service %s:%s", h.host, h.port)
}
