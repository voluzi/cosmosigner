package server

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStaticNodes(t *testing.T) {
	s := StaticNodes{"1.2.3.4:5555", "5.6.7.8:5555"}
	got, err := s.Nodes()
	require.NoError(t, err)
	require.Equal(t, []string{"1.2.3.4:5555", "5.6.7.8:5555"}, got)
}

func TestNewHeadlessServiceNodes(t *testing.T) {
	h, err := NewHeadlessServiceNodes("sentries.ns.svc.cluster.local:5555")
	require.NoError(t, err)
	require.Equal(t, "headless-service sentries.ns.svc.cluster.local:5555", h.Describe())

	for _, bad := range []string{"", "no-port", "host:", ":5555"} {
		_, err := NewHeadlessServiceNodes(bad)
		require.Error(t, err, "input %q should be rejected", bad)
	}
}
