package state

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/hashicorp/raft"
)

// TLSConfig configures mutual TLS for the inter-replica raft transport. All
// three files must be set to enable it; otherwise the transport is plain TCP
// (only safe on a trusted/isolated network).
type TLSConfig struct {
	CertFile string
	KeyFile  string
	CAFile   string
}

// Enabled reports whether mutual TLS is configured.
func (t TLSConfig) Enabled() bool {
	return t.CertFile != "" && t.KeyFile != "" && t.CAFile != ""
}

// tlsStreamLayer is a raft.StreamLayer that authenticates and encrypts
// inter-replica traffic with mutual TLS: every peer must present a certificate
// signed by the configured CA (RequireAndVerifyClientCert), and dialers verify
// the peer's certificate chain.
type tlsStreamLayer struct {
	listener  net.Listener
	advertise net.Addr
	clientCfg *tls.Config
}

func newTLSStreamLayer(bindAddr string, advertise net.Addr, cfg TLSConfig) (*tlsStreamLayer, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load raft TLS keypair: %w", err)
	}
	caPEM, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("read raft TLS CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("no certificates found in raft TLS CA %q", cfg.CAFile)
	}

	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
	ln, err := tls.Listen("tcp", bindAddr, serverCfg)
	if err != nil {
		return nil, fmt.Errorf("raft TLS listen on %s: %w", bindAddr, err)
	}

	return &tlsStreamLayer{
		listener:  ln,
		advertise: advertise,
		clientCfg: &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      pool,
			MinVersion:   tls.VersionTLS12,
		},
	}, nil
}

func (s *tlsStreamLayer) Accept() (net.Conn, error) { return s.listener.Accept() }
func (s *tlsStreamLayer) Close() error              { return s.listener.Close() }
func (s *tlsStreamLayer) Addr() net.Addr            { return s.advertise }

func (s *tlsStreamLayer) Dial(address raft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	cfg := s.clientCfg.Clone()
	// Verify the peer cert's SAN against the host we dial. Certs must list the
	// advertise host (IP or DNS) in their SANs.
	if host, _, err := net.SplitHostPort(string(address)); err == nil {
		cfg.ServerName = host
	}
	return tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", string(address), cfg)
}
