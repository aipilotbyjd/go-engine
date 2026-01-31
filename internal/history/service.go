package history

import (
	"context"
	"errors"
	"log/slog"
	"sync"
)

var (
	ErrServiceNotRunning = errors.New("history service is not running")
	ErrServiceAlreadyRunning = errors.New("history service is already running")
)

type EventStore interface {
	AppendEvents(ctx context.Context, key ExecutionKey, events []*HistoryEvent, expectedVersion int64) error
	GetEvents(ctx context.Context, key ExecutionKey, firstEventID, lastEventID int64) ([]*HistoryEvent, error)
}

type MutableState struct {
	ExecutionInfo     *ExecutionInfo
	NextEventID       int64
	PendingActivities map[int64]*ActivityInfo
	PendingTimers     map[string]*TimerInfo
	CompletedNodes    map[string]*NodeResult
	BufferedEvents    []*HistoryEvent
	DBVersion         int64
}

type MutableStateStore interface {
	GetMutableState(ctx context.Context, key ExecutionKey) (*MutableState, error)
	UpdateMutableState(ctx context.Context, key ExecutionKey, state *MutableState, expectedVersion int64) error
}

type ShardController interface {
	GetShardForExecution(key ExecutionKey) (Shard, error)
	GetShardIDForExecution(key ExecutionKey) int32
	Stop()
}

type Shard interface {
	GetID() int32
}

type Service struct {
	shardController ShardController
	eventStore      EventStore
	stateStore      MutableStateStore
	logger          *slog.Logger

	running bool
	mu      sync.RWMutex
}

func NewService(
	shardController ShardController,
	eventStore EventStore,
	stateStore MutableStateStore,
	logger *slog.Logger,
) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		shardController: shardController,
		eventStore:      eventStore,
		stateStore:      stateStore,
		logger:          logger,
		running:         false,
	}
}

func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return ErrServiceAlreadyRunning
	}

	s.logger.Info("starting history service")
	s.running = true
	return nil
}

func (s *Service) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	s.logger.Info("stopping history service")
	
	if s.shardController != nil {
		s.shardController.Stop()
	}

	s.running = false
	return nil
}

func (s *Service) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

func (s *Service) RecordEvent(ctx context.Context, key ExecutionKey, event *HistoryEvent) error {
	s.mu.RLock()
	running := s.running
	s.mu.RUnlock()

	if !running {
		return ErrServiceNotRunning
	}

	shard, err := s.shardController.GetShardForExecution(key)
	if err != nil {
		return err
	}

	s.logger.Debug("recording event",
		"shard_id", shard.GetID(),
		"namespace_id", key.NamespaceID,
		"workflow_id", key.WorkflowID,
		"run_id", key.RunID,
		"event_id", event.EventID,
		"event_type", event.EventType,
	)

	state, err := s.stateStore.GetMutableState(ctx, key)
	if err != nil {
		state = &MutableState{
			ExecutionInfo: &ExecutionInfo{
				NamespaceID: key.NamespaceID,
				WorkflowID:  key.WorkflowID,
				RunID:       key.RunID,
			},
			NextEventID:       1,
			PendingActivities: make(map[int64]*ActivityInfo),
			PendingTimers:     make(map[string]*TimerInfo),
			CompletedNodes:    make(map[string]*NodeResult),
			BufferedEvents:    make([]*HistoryEvent, 0),
			DBVersion:         0,
		}
	}

	expectedVersion := state.DBVersion

	if err := s.eventStore.AppendEvents(ctx, key, []*HistoryEvent{event}, expectedVersion); err != nil {
		return err
	}

	state.NextEventID = event.EventID + 1
	state.DBVersion++

	if err := s.stateStore.UpdateMutableState(ctx, key, state, expectedVersion); err != nil {
		s.logger.Warn("failed to update mutable state after recording event",
			"error", err,
			"workflow_id", key.WorkflowID,
		)
	}

	return nil
}

func (s *Service) RecordEvents(ctx context.Context, key ExecutionKey, events []*HistoryEvent) error {
	s.mu.RLock()
	running := s.running
	s.mu.RUnlock()

	if !running {
		return ErrServiceNotRunning
	}

	if len(events) == 0 {
		return nil
	}

	shard, err := s.shardController.GetShardForExecution(key)
	if err != nil {
		return err
	}

	s.logger.Debug("recording events",
		"shard_id", shard.GetID(),
		"namespace_id", key.NamespaceID,
		"workflow_id", key.WorkflowID,
		"run_id", key.RunID,
		"event_count", len(events),
	)

	state, err := s.stateStore.GetMutableState(ctx, key)
	if err != nil {
		state = &MutableState{
			ExecutionInfo: &ExecutionInfo{
				NamespaceID: key.NamespaceID,
				WorkflowID:  key.WorkflowID,
				RunID:       key.RunID,
			},
			NextEventID:       1,
			PendingActivities: make(map[int64]*ActivityInfo),
			PendingTimers:     make(map[string]*TimerInfo),
			CompletedNodes:    make(map[string]*NodeResult),
			BufferedEvents:    make([]*HistoryEvent, 0),
			DBVersion:         0,
		}
	}

	expectedVersion := state.DBVersion

	if err := s.eventStore.AppendEvents(ctx, key, events, expectedVersion); err != nil {
		return err
	}

	lastEvent := events[len(events)-1]
	state.NextEventID = lastEvent.EventID + 1
	state.DBVersion++

	if err := s.stateStore.UpdateMutableState(ctx, key, state, expectedVersion); err != nil {
		s.logger.Warn("failed to update mutable state after recording events",
			"error", err,
			"workflow_id", key.WorkflowID,
		)
	}

	return nil
}

func (s *Service) GetHistory(ctx context.Context, key ExecutionKey, firstEventID, lastEventID int64) ([]*HistoryEvent, error) {
	s.mu.RLock()
	running := s.running
	s.mu.RUnlock()

	if !running {
		return nil, ErrServiceNotRunning
	}

	if firstEventID <= 0 {
		firstEventID = 1
	}
	if lastEventID <= 0 {
		lastEventID = int64(^uint64(0) >> 1)
	}

	return s.eventStore.GetEvents(ctx, key, firstEventID, lastEventID)
}

func (s *Service) GetMutableState(ctx context.Context, key ExecutionKey) (*MutableState, error) {
	s.mu.RLock()
	running := s.running
	s.mu.RUnlock()

	if !running {
		return nil, ErrServiceNotRunning
	}

	return s.stateStore.GetMutableState(ctx, key)
}

func (s *Service) GetShardForExecution(key ExecutionKey) (Shard, error) {
	return s.shardController.GetShardForExecution(key)
}

func (s *Service) GetShardIDForExecution(key ExecutionKey) int32 {
	return s.shardController.GetShardIDForExecution(key)
}
