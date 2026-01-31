package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/linkflow/engine/internal/worker/executor"
	"github.com/linkflow/engine/internal/worker/poller"
	"github.com/linkflow/engine/internal/worker/retry"
)

type Service struct {
	executors   map[string]executor.Executor
	taskPoller  *poller.Poller
	retryPolicy *retry.Policy
	logger      *slog.Logger
	wg          sync.WaitGroup
	stopCh      chan struct{}

	mu      sync.RWMutex
	running bool
}

type Config struct {
	TaskQueue    string
	Identity     string
	MatchingAddr string
	PollInterval time.Duration
	RetryPolicy  *retry.Policy
	Logger       *slog.Logger
}

func NewService(cfg Config) *Service {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.RetryPolicy == nil {
		cfg.RetryPolicy = retry.DefaultPolicy()
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = time.Second
	}

	p := poller.New(poller.Config{
		TaskQueue:    cfg.TaskQueue,
		Identity:     cfg.Identity,
		MatchingAddr: cfg.MatchingAddr,
		PollInterval: cfg.PollInterval,
		Logger:       cfg.Logger,
	})

	svc := &Service{
		executors:   make(map[string]executor.Executor),
		taskPoller:  p,
		retryPolicy: cfg.RetryPolicy,
		logger:      cfg.Logger,
		stopCh:      make(chan struct{}),
	}

	p.SetHandler(svc.handleTask)

	return svc
}

func (s *Service) RegisterExecutor(exec executor.Executor) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.executors[exec.NodeType()] = exec
	s.logger.Info("registered executor", slog.String("node_type", exec.NodeType()))
}

func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return ErrServiceAlreadyStart
	}
	s.running = true
	s.stopCh = make(chan struct{})
	s.mu.Unlock()

	if err := s.taskPoller.Start(ctx); err != nil {
		return fmt.Errorf("failed to start task poller: %w", err)
	}

	s.logger.Info("worker service started")
	return nil
}

func (s *Service) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return ErrServiceNotRunning
	}
	s.running = false
	close(s.stopCh)
	s.mu.Unlock()

	s.taskPoller.Stop()
	s.wg.Wait()

	s.logger.Info("worker service stopped")
	return nil
}

func (s *Service) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

func (s *Service) handleTask(task *poller.Task) (*poller.TaskResult, error) {
	s.wg.Add(1)
	defer s.wg.Done()

	workerTask := &Task{
		TaskID:     task.TaskID,
		WorkflowID: task.WorkflowID,
		RunID:      task.RunID,
		NodeType:   task.NodeType,
		NodeID:     task.NodeID,
		Config:     task.Config,
		Input:      task.Input,
		Attempt:    task.Attempt,
		TimeoutSec: task.TimeoutSec,
	}

	result, err := s.ProcessTask(context.Background(), workerTask)
	if err != nil {
		return nil, err
	}

	return &poller.TaskResult{
		TaskID:    result.TaskID,
		Output:    result.Output,
		Error:     result.Error,
		ErrorType: result.ErrorType,
		Logs:      result.Logs,
	}, nil
}

func (s *Service) ProcessTask(ctx context.Context, task *Task) (*TaskResult, error) {
	s.logger.Info("processing task",
		slog.String("task_id", task.TaskID),
		slog.String("node_type", task.NodeType),
		slog.String("node_id", task.NodeID),
		slog.Int("attempt", int(task.Attempt)),
	)

	s.mu.RLock()
	exec, ok := s.executors[task.NodeType]
	s.mu.RUnlock()

	if !ok {
		return &TaskResult{
			TaskID:    task.TaskID,
			Error:     fmt.Sprintf("no executor registered for node type: %s", task.NodeType),
			ErrorType: ErrorTypeNonRetryable,
		}, ErrExecutorNotFound
	}

	timeout := time.Duration(task.TimeoutSec) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req := &executor.ExecuteRequest{
		NodeType: task.NodeType,
		NodeID:   task.NodeID,
		Config:   task.Config,
		Input:    task.Input,
		Attempt:  task.Attempt,
		Timeout:  timeout,
	}

	resp, err := exec.Execute(execCtx, req)
	if err != nil {
		s.logger.Error("executor error",
			slog.String("task_id", task.TaskID),
			slog.String("error", err.Error()),
		)
		return &TaskResult{
			TaskID:    task.TaskID,
			Error:     err.Error(),
			ErrorType: ErrorTypeRetryable,
		}, err
	}

	result := &TaskResult{
		TaskID: task.TaskID,
		Output: resp.Output,
	}

	if resp.Error != nil {
		result.Error = resp.Error.Message
		result.ErrorType = resp.Error.Type

		if s.retryPolicy.ShouldRetry(task.Attempt, resp.Error.Type, resp.Error.Message) {
			delay := s.retryPolicy.NextRetryDelay(task.Attempt)
			s.logger.Info("task will be retried",
				slog.String("task_id", task.TaskID),
				slog.Int("attempt", int(task.Attempt)),
				slog.Duration("retry_delay", delay),
			)
		}
	}

	if len(resp.Logs) > 0 {
		logsJSON, _ := json.Marshal(resp.Logs)
		result.Logs = logsJSON
	}

	s.logger.Info("task processed",
		slog.String("task_id", task.TaskID),
		slog.Duration("duration", resp.Duration),
		slog.Bool("has_error", resp.Error != nil),
	)

	return result, nil
}

func (s *Service) GetExecutor(nodeType string) (executor.Executor, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	exec, ok := s.executors[nodeType]
	return exec, ok
}
