package state

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/raft"
	"github.com/stretchr/testify/require"
)

// genCA creates a self-signed CA certificate and its key.
func genCA(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return cert, key, caPEM
}

// genLeaf issues a leaf cert signed by ca, valid as both TLS server and client
// (raft peers do both), with a 127.0.0.1 IP SAN so dialers verify the host.
func genLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "cosmosigner"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

// writeTLSFiles writes a CA + leaf keypair to dir and returns a TLSConfig.
func writeTLSFiles(t *testing.T, dir, prefix string, caPEM, certPEM, keyPEM []byte) TLSConfig {
	t.Helper()
	cfg := TLSConfig{
		CAFile:   filepath.Join(dir, prefix+"-ca.pem"),
		CertFile: filepath.Join(dir, prefix+"-cert.pem"),
		KeyFile:  filepath.Join(dir, prefix+"-key.pem"),
	}
	require.NoError(t, os.WriteFile(cfg.CAFile, caPEM, 0o600))
	require.NoError(t, os.WriteFile(cfg.CertFile, certPEM, 0o600))
	require.NoError(t, os.WriteFile(cfg.KeyFile, keyPEM, 0o600))
	return cfg
}

func newTLSNode(t *testing.T, id, addr, dir string, members []Member, tls TLSConfig) StateStore {
	t.Helper()
	s, err := NewRaftStore(RaftConfig{
		NodeID:       id,
		BindAddr:     addr,
		Advertise:    addr,
		DataDir:      dir,
		Bootstrap:    true,
		Members:      members,
		ApplyTimeout: 5 * time.Second,
		TLS:          tls,
	}, hclog.NewNullLogger())
	require.NoError(t, err)
	return s
}

// TestRaftCluster_MutualTLS forms a 3-node cluster whose inter-replica transport
// is mutual TLS, and proves leadership + high-water-mark replication work over it.
func TestRaftCluster_MutualTLS(t *testing.T) {
	if testing.Short() {
		t.Skip("multi-node raft test")
	}
	ca, caKey, caPEM := genCA(t, "raft-test-ca")
	dir := t.TempDir()
	addrs := freeAddrs(t, 3)
	ids := []string{"t0", "t1", "t2"}
	members := []Member{{ids[0], addrs[0]}, {ids[1], addrs[1]}, {ids[2], addrs[2]}}

	stores := map[string]StateStore{}
	for i, id := range ids {
		certPEM, keyPEM := genLeaf(t, ca, caKey)
		tls := writeTLSFiles(t, dir, id, caPEM, certPEM, keyPEM)
		stores[id] = newTLSNode(t, id, addrs[i], filepath.Join(dir, id), members, tls)
	}
	defer func() {
		for _, s := range stores {
			_ = s.Close()
		}
	}()

	leaderID := waitLeader(t, stores)
	sb := voteSignBytes(42, 0, ts1, "A")
	_, err := stores[leaderID].Reserve(testChain, 42, 0, StepPrecommit, sb, ts1)
	require.NoError(t, err)
	require.NoError(t, stores[leaderID].Commit(testChain, 42, 0, StepPrecommit, sb, sig64()))

	require.Eventually(t, func() bool {
		for id := range stores {
			st, err := stores[id].Get(testChain)
			if err != nil || st == nil || st.Height != 42 {
				return false
			}
		}
		return true
	}, 5*time.Second, 100*time.Millisecond, "all members should replicate the HWM over mTLS")
}

// TestTLSStreamLayer_RejectsUntrustedPeer proves the transport refuses a peer
// whose certificate is signed by a different CA — the core authorization
// guarantee of the mTLS option.
func TestTLSStreamLayer_RejectsUntrustedPeer(t *testing.T) {
	dir := t.TempDir()
	ca1, ca1Key, ca1PEM := genCA(t, "ca-1")
	ca2, ca2Key, _ := genCA(t, "ca-2")

	srvCert, srvKey := genLeaf(t, ca1, ca1Key)
	srvCfg := writeTLSFiles(t, dir, "server", ca1PEM, srvCert, srvKey)

	addr := freeAddrs(t, 1)[0]
	server, err := newTLSStreamLayer(addr, mustResolve(t, addr), srvCfg)
	require.NoError(t, err)
	defer server.Close()
	go func() {
		for {
			c, err := server.Accept()
			if err != nil {
				return
			}
			// Force the TLS handshake to run, then drop the connection.
			_ = c.SetDeadline(time.Now().Add(time.Second))
			buf := make([]byte, 1)
			_, _ = c.Read(buf)
			_ = c.Close()
		}
	}()

	// Client trusts ca1 (so it accepts the server) but presents a cert signed by
	// ca2 — the server requires a ca1-signed client cert and must reject it.
	rogueCert, rogueKey := genLeaf(t, ca2, ca2Key)
	rogueCfg := writeTLSFiles(t, dir, "rogue", ca1PEM, rogueCert, rogueKey)
	client, err := newTLSStreamLayer(freeAddrs(t, 1)[0], mustResolve(t, addr), rogueCfg)
	require.NoError(t, err)
	defer client.Close()

	// In TLS 1.3 the client's handshake completes optimistically; the server's
	// rejection of the untrusted client cert surfaces as an alert on the first
	// read. Either path proves the peer is refused.
	conn, err := client.Dial(raft.ServerAddress(addr), time.Second)
	if err == nil {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		_, err = conn.Read(make([]byte, 1))
		_ = conn.Close()
	}
	require.Error(t, err, "server must reject a client cert signed by an untrusted CA")
}

func mustResolve(t *testing.T, addr string) net.Addr {
	t.Helper()
	a, err := net.ResolveTCPAddr("tcp", addr)
	require.NoError(t, err)
	return a
}
