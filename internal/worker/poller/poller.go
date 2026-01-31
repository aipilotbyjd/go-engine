package poller

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

type Task struct {
	TaskID     string `json:"task_id"`
	WorkflowID string `json:"workflow_id"`
	RunID      string `json:"run_id"`
	NodeType   string `json:"node_type"`
	NodeID     string `json:"node_id"`
	Config     []byte `json:"config"`
	Input      []byte `json:"input"`
	Attempt    int32  `json:"attempt"`
	TimeoutSec int32  `json:"timeout_sec"`
}

type TaskResult struct {
	TaskID    string `json:"task_id"`
	Output    []byte `json:"output"`
	Error     string `json:"error"`
	ErrorType string `json:"error_type"`
	Logs      []byte `json:"logs"`
}

type TaskHandler func(task *Task) (*TaskResult, error)

type Poller struct {
	taskQueue    string
	identity     string
	matchingAddr string
	pollInterval time.Duration
	logger       *slog.Logger

	handler TaskHandler
	wg      sync.WaitGroup
	stopCh  chan struct{}
	running bool
	mu      sync.Mutex
}

type Config struct {
	TaskQueue    string
	Identity     string
	MatchingAddr string
	PollInterval time.Duration
	Logger       *slog.Logger
}

func New(cfg Config) *Poller {
	if cfg.PollInterval == 0 {
		cfg.PollInterval = time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return &Poller{
		taskQueue:    cfg.TaskQueue,
		identity:     cfg.Identity,
		matchingAddr: cfg.MatchingAddr,
		pollInterval: cfg.PollInterval,
		logger:       cfg.Logger,
		stopCh:       make(chan struct{}),
	}
}

func (p *Poller) SetHandler(handler TaskHandler) {
	p.handler = handler
}

func (p *Poller) Start(ctx context.Context) error {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return nil
	}
	p.running = true
	p.stopCh = make(chan struct{})
	p.mu.Unlock()

	p.wg.Add(1)
	go p.pollLoop(ctx)

	p.logger.Info("poller started",
		slog.String("task_queue", p.taskQueue),
		slog.String("identity", p.identity),
	)

	return nil
}

func (p *Poller) Stop() {
	p.mu.Lock()
	if !p.running {
		p.mu.Unlock()
		return
	}
	p.running = false
	close(p.stopCh)
	p.mu.Unlock()

	p.wg.Wait()
	p.logger.Info("poller stopped")
}

func (p *Poller) pollLoop(ctx context.Context) {
	defer p.wg.Done()

	ticker := time.NewTicker(p.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopCh:
			return
		case <-ticker.C:
			task, err := p.Poll(ctx)
			if err != nil {
				p.logger.Error("poll failed", slog.String("error", err.Error()))
				continue
			}
			if task == nil {
				continue
			}

			if p.handler != nil {
				result, err := p.handler(task)
				if err != nil {
					p.logger.Error("task handler failed",
						slog.String("task_id", task.TaskID),
						slog.String("error", err.Error()),
					)
				} else {
					p.logger.Debug("task completed",
						slog.String("task_id", task.TaskID),
						slog.String("error_type", result.ErrorType),
					)
				}
			}
		}
	}
}

func (p *Poller) Poll(ctx context.Context) (*Task, error) {
	p.logger.Debug("polling for tasks",
		slog.String("task_queue", p.taskQueue),
		slog.String("matching_addr", p.matchingAddr),
	)

	return nil, nil
}

func (p *Poller) IsRunning() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.running
}
