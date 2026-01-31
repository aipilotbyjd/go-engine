package matching

import (
	"context"
	"log/slog"
	"sync"

	"github.com/linkflow/engine/internal/matching/engine"
	"github.com/linkflow/engine/internal/matching/partition"
)

const (
	defaultRateLimit = 1000.0
	defaultBurst     = 100
)

type Service struct {
	partitionMgr *partition.Manager
	taskQueues   map[string]*engine.TaskQueue
	logger       *slog.Logger
	mu           sync.RWMutex
}

type Config struct {
	NumPartitions int32
	Replicas      int
	Logger        *slog.Logger
}

func NewService(cfg Config) *Service {
	if cfg.NumPartitions <= 0 {
		cfg.NumPartitions = 4
	}
	if cfg.Replicas <= 0 {
		cfg.Replicas = 100
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return &Service{
		partitionMgr: partition.NewManager(cfg.NumPartitions, cfg.Replicas),
		taskQueues:   make(map[string]*engine.TaskQueue),
		logger:       cfg.Logger,
	}
}

func (s *Service) AddTask(ctx context.Context, taskQueueName string, task *engine.Task) error {
	tq := s.GetOrCreateTaskQueue(taskQueueName, engine.TaskQueueKindNormal)
	if !tq.AddTask(task) {
		s.logger.Warn("task already exists",
			slog.String("task_id", task.ID),
			slog.String("task_queue", taskQueueName),
		)
	}
	return nil
}

func (s *Service) PollTask(ctx context.Context, taskQueueName string, identity string) (*engine.Task, error) {
	s.mu.RLock()
	tq, exists := s.taskQueues[taskQueueName]
	s.mu.RUnlock()

	if !exists {
		return nil, ErrTaskQueueNotFound
	}

	task, err := tq.Poll(ctx, identity)
	if err != nil {
		return nil, err
	}

	return task, nil
}

func (s *Service) CompleteTask(ctx context.Context, taskQueueName string, taskID string) error {
	s.mu.RLock()
	tq, exists := s.taskQueues[taskQueueName]
	s.mu.RUnlock()

	if !exists {
		return ErrTaskQueueNotFound
	}

	if !tq.CompleteTask(taskID) {
		return ErrTaskNotFound
	}

	return nil
}

func (s *Service) GetOrCreateTaskQueue(name string, kind engine.TaskQueueKind) *engine.TaskQueue {
	s.mu.RLock()
	tq, exists := s.taskQueues[name]
	s.mu.RUnlock()

	if exists {
		return tq
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if tq, exists = s.taskQueues[name]; exists {
		return tq
	}

	partition := s.partitionMgr.GetPartitionForTaskQueue(name)
	tq = partition.GetOrCreateTaskQueue(name, kind, defaultRateLimit, defaultBurst)
	s.taskQueues[name] = tq

	s.logger.Info("created task queue",
		slog.String("name", name),
		slog.Int("kind", int(kind)),
		slog.Int("partition", int(partition.ID)),
	)

	return tq
}

func (s *Service) GetTaskQueue(name string) (*engine.TaskQueue, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tq, exists := s.taskQueues[name]
	if !exists {
		return nil, ErrTaskQueueNotFound
	}
	return tq, nil
}

func (s *Service) PartitionManager() *partition.Manager {
	return s.partitionMgr
}
