package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/hashicorp/raft"

	"github.com/voluzi/cosmosigner/internal/clusterid"
)

const snapshotMagic = "cosmosigner-state-v1\n"

type snapshotState struct {
	ClusterID string                `json:"cluster_id"`
	State     map[string]*SignState `json:"state"`
}

// Snapshot serializes the immutable cluster identity with the high-water-mark map.
func (f *fsm) Snapshot() (raft.FSMSnapshot, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	payload, err := json.Marshal(snapshotState{ClusterID: f.clusterID, State: f.state})
	if err != nil {
		return nil, err
	}
	data := append([]byte(snapshotMagic), payload...)
	return &fsmSnapshot{data: data}, nil
}

// Restore replaces the state from a snapshot.
func (f *fsm) Restore(rc io.ReadCloser) error {
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		return fmt.Errorf("read snapshot: %w", err)
	}
	var clusterID string
	state := make(map[string]*SignState)
	if bytes.HasPrefix(data, []byte("cosmosigner-state-v")) {
		if !bytes.HasPrefix(data, []byte(snapshotMagic)) {
			return errors.New("decode snapshot: unsupported snapshot format version")
		}
		var envelope struct {
			ClusterID *string         `json:"cluster_id"`
			State     json.RawMessage `json:"state"`
		}
		if err := json.Unmarshal(data[len(snapshotMagic):], &envelope); err != nil {
			return fmt.Errorf("decode snapshot: %w", err)
		}
		if envelope.ClusterID == nil {
			return errors.New("decode snapshot: cluster_id must be a string")
		}
		clusterID = *envelope.ClusterID
		if clusterID != "" {
			if err := clusterid.Validate(clusterID); err != nil {
				return fmt.Errorf("decode snapshot: invalid cluster_id: %w", err)
			}
		}
		if len(envelope.State) == 0 {
			return errors.New("decode snapshot: state field is required")
		}
		if err := json.Unmarshal(envelope.State, &state); err != nil {
			return fmt.Errorf("decode snapshot: %w", err)
		}
	} else if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("decode snapshot: %w", err)
	}
	if state == nil {
		return errors.New("decode snapshot: state must be a JSON object")
	}
	for chainID, signState := range state {
		if signState == nil {
			return fmt.Errorf("decode snapshot: state for chain %q must not be null", chainID)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clusterID = clusterID
	f.state = state
	return nil
}

type fsmSnapshot struct{ data []byte }

func (s *fsmSnapshot) Persist(sink raft.SnapshotSink) error {
	if _, err := sink.Write(s.data); err != nil {
		_ = sink.Cancel()
		return err
	}
	return sink.Close()
}

func (s *fsmSnapshot) Release() {}
