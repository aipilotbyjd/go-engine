package store

import (
	"context"
	"errors"
	"sync"

	"github.com/linkflow/engine/internal/history"
	"github.com/linkflow/engine/internal/history/engine"
)

var (
	ErrVersionMismatch   = errors.New("version mismatch")
	ErrExecutionNotFound = errors.New("execution not found")
	ErrEventNotFound     = errors.New("event not found")
)

type executionKeyString string

func makeKey(key history.ExecutionKey) executionKeyString {
	return executionKeyString(key.NamespaceID + "/" + key.WorkflowID + "/" + key.RunID)
}

type MemoryEventStore struct {
	mu       sync.RWMutex
	events   map[executionKeyString][]*history.HistoryEvent
	versions map[executionKeyString]int64
}

func NewMemoryEventStore() *MemoryEventStore {
	return &MemoryEventStore{
		events:   make(map[executionKeyString][]*history.HistoryEvent),
		versions: make(map[executionKeyString]int64),
	}
}

func (s *MemoryEventStore) AppendEvents(ctx context.Context, key history.ExecutionKey, events []*history.HistoryEvent, expectedVersion int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	k := makeKey(key)
	currentVersion := s.versions[k]

	if expectedVersion >= 0 && currentVersion != expectedVersion {
		return ErrVersionMismatch
	}

	s.events[k] = append(s.events[k], events...)
	s.versions[k] = currentVersion + int64(len(events))

	return nil
}

func (s *MemoryEventStore) GetEvents(ctx context.Context, key history.ExecutionKey, firstEventID, lastEventID int64) ([]*history.HistoryEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	k := makeKey(key)
	allEvents, exists := s.events[k]
	if !exists {
		return nil, ErrExecutionNotFound
	}

	var result []*history.HistoryEvent
	for _, event := range allEvents {
		if event.EventID >= firstEventID && event.EventID <= lastEventID {
			result = append(result, event)
		}
	}

	return result, nil
}

func (s *MemoryEventStore) GetVersion(key history.ExecutionKey) int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.versions[makeKey(key)]
}

func (s *MemoryEventStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = make(map[executionKeyString][]*history.HistoryEvent)
	s.versions = make(map[executionKeyString]int64)
}

type MemoryMutableStateStore struct {
	mu     sync.RWMutex
	states map[executionKeyString]*engine.MutableState
}

func NewMemoryMutableStateStore() *MemoryMutableStateStore {
	return &MemoryMutableStateStore{
		states: make(map[executionKeyString]*engine.MutableState),
	}
}

func (s *MemoryMutableStateStore) GetMutableState(ctx context.Context, key history.ExecutionKey) (*engine.MutableState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	k := makeKey(key)
	state, exists := s.states[k]
	if !exists {
		return nil, ErrExecutionNotFound
	}

	return state.Clone(), nil
}

func (s *MemoryMutableStateStore) UpdateMutableState(ctx context.Context, key history.ExecutionKey, state *engine.MutableState, expectedVersion int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	k := makeKey(key)
	existing, exists := s.states[k]

	if expectedVersion >= 0 {
		if !exists && expectedVersion != 0 {
			return ErrVersionMismatch
		}
		if exists && existing.DBVersion != expectedVersion {
			return ErrVersionMismatch
		}
	}

	clone := state.Clone()
	clone.DBVersion = state.DBVersion + 1
	s.states[k] = clone

	return nil
}

func (s *MemoryMutableStateStore) DeleteMutableState(ctx context.Context, key history.ExecutionKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	k := makeKey(key)
	delete(s.states, k)
	return nil
}

func (s *MemoryMutableStateStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states = make(map[executionKeyString]*engine.MutableState)
}
