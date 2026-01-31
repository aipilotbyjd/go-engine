package partition

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/linkflow/engine/internal/matching/engine"
)

type Manager struct {
	numPartitions int32
	partitions    map[int32]*Partition
	hashRing      *Ring
	mu            sync.RWMutex
}

type Partition struct {
	ID         int32
	TaskQueues map[string]*engine.TaskQueue
	Load       atomic.Int64
	LastActive time.Time
	mu         sync.RWMutex
}

func NewManager(numPartitions int32, replicas int) *Manager {
	m := &Manager{
		numPartitions: numPartitions,
		partitions:    make(map[int32]*Partition),
		hashRing:      NewRing(replicas),
	}

	for i := int32(0); i < numPartitions; i++ {
		m.partitions[i] = &Partition{
			ID:         i,
			TaskQueues: make(map[string]*engine.TaskQueue),
			LastActive: time.Now(),
		}
		m.hashRing.Add(i)
	}

	return m
}

func (m *Manager) GetPartition(partitionID int32) *Partition {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.partitions[partitionID]
}

func (m *Manager) GetPartitionForTaskQueue(taskQueueName string) *Partition {
	m.mu.RLock()
	defer m.mu.RUnlock()

	partitionID := m.hashRing.Get(taskQueueName)
	return m.partitions[partitionID]
}

func (m *Manager) NumPartitions() int32 {
	return m.numPartitions
}

func (p *Partition) GetOrCreateTaskQueue(name string, kind engine.TaskQueueKind, rateLimit float64, burst int) *engine.TaskQueue {
	p.mu.Lock()
	defer p.mu.Unlock()

	if tq, exists := p.TaskQueues[name]; exists {
		return tq
	}

	tq := engine.NewTaskQueue(name, kind, rateLimit, burst)
	p.TaskQueues[name] = tq
	p.LastActive = time.Now()
	return tq
}

func (p *Partition) GetTaskQueue(name string) *engine.TaskQueue {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.TaskQueues[name]
}
