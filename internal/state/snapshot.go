package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/hashicorp/raft"
)

// Snapshot serializes the (tiny) high-water-mark map.
func (f *fsm) Snapshot() (raft.FSMSnapshot, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	data, err := json.Marshal(f.state)
	if err != nil {
		return nil, err
	}
	return &fsmSnapshot{data: data}, nil
}

// Restore replaces the state from a snapshot.
func (f *fsm) Restore(rc io.ReadCloser) error {
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		return fmt.Errorf("read snapshot: %w", err)
	}
	state := make(map[string]*SignState)
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("decode snapshot: %w", err)
	}
	if state == nil {
		return errors.New("decode snapshot: state must be a JSON object")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
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
