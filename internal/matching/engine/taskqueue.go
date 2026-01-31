package engine

import (
	"container/list"
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type TaskQueue struct {
	name        string
	kind        TaskQueueKind
	tasks       *list.List
	tasksMap    map[string]*list.Element
	pollers     *list.List
	rateLimiter *rate.Limiter
	metrics     *Metrics
	mu          sync.Mutex
}

func NewTaskQueue(name string, kind TaskQueueKind, rateLimit float64, burst int) *TaskQueue {
	return &TaskQueue{
		name:        name,
		kind:        kind,
		tasks:       list.New(),
		tasksMap:    make(map[string]*list.Element),
		pollers:     list.New(),
		rateLimiter: rate.NewLimiter(rate.Limit(rateLimit), burst),
		metrics:     NewMetrics(),
	}
}

func (tq *TaskQueue) Name() string {
	return tq.name
}

func (tq *TaskQueue) Kind() TaskQueueKind {
	return tq.kind
}

func (tq *TaskQueue) Metrics() *Metrics {
	return tq.metrics
}

func (tq *TaskQueue) AddTask(task *Task) bool {
	tq.mu.Lock()
	defer tq.mu.Unlock()

	if _, exists := tq.tasksMap[task.ID]; exists {
		return false
	}

	tq.metrics.TaskAdded()

	if tq.tryDispatchLocked(task) {
		return true
	}

	elem := tq.tasks.PushBack(task)
	tq.tasksMap[task.ID] = elem
	return true
}

func (tq *TaskQueue) Poll(ctx context.Context, identity string) (*Task, error) {
	tq.mu.Lock()

	if !tq.rateLimiter.Allow() {
		tq.mu.Unlock()
		return nil, ErrRateLimited
	}

	if task := tq.getNextTaskLocked(); task != nil {
		tq.mu.Unlock()
		tq.metrics.TaskDispatched()
		tq.metrics.RecordLatency(time.Since(task.ScheduledTime))
		return task, nil
	}

	poller := &Poller{
		Identity:  identity,
		ResultCh:  make(chan *Task, 1),
		CreatedAt: time.Now(),
	}
	elem := tq.pollers.PushBack(poller)
	tq.metrics.PollersWaiting.Add(1)
	tq.mu.Unlock()

	defer func() {
		tq.mu.Lock()
		tq.pollers.Remove(elem)
		tq.metrics.PollersWaiting.Add(-1)
		tq.mu.Unlock()
	}()

	select {
	case task := <-poller.ResultCh:
		return task, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (tq *TaskQueue) CompleteTask(taskID string) bool {
	tq.mu.Lock()
	defer tq.mu.Unlock()

	if elem, exists := tq.tasksMap[taskID]; exists {
		tq.tasks.Remove(elem)
		delete(tq.tasksMap, taskID)
		return true
	}
	return false
}

func (tq *TaskQueue) getNextTaskLocked() *Task {
	elem := tq.tasks.Front()
	if elem == nil {
		return nil
	}
	task := elem.Value.(*Task)
	tq.tasks.Remove(elem)
	delete(tq.tasksMap, task.ID)
	return task
}

func (tq *TaskQueue) tryDispatchLocked(task *Task) bool {
	elem := tq.pollers.Front()
	if elem == nil {
		return false
	}

	poller := elem.Value.(*Poller)
	tq.pollers.Remove(elem)

	task.StartedTime = time.Now()
	poller.ResultCh <- task

	tq.metrics.TaskDispatched()
	tq.metrics.RecordLatency(time.Since(task.ScheduledTime))
	return true
}

func (tq *TaskQueue) PendingTaskCount() int {
	tq.mu.Lock()
	defer tq.mu.Unlock()
	return tq.tasks.Len()
}

func (tq *TaskQueue) PollerCount() int {
	tq.mu.Lock()
	defer tq.mu.Unlock()
	return tq.pollers.Len()
}

var ErrRateLimited = errRateLimited{}

type errRateLimited struct{}

func (errRateLimited) Error() string { return "rate limited" }
