package engine

import (
	"sync"
	"sync/atomic"
	"time"
)

const latencyBufferSize = 1000

type Metrics struct {
	TasksAdded      atomic.Int64
	TasksDispatched atomic.Int64
	PollersWaiting  atomic.Int64

	latencies    []time.Duration
	latencyIndex int
	mu           sync.Mutex
}

func NewMetrics() *Metrics {
	return &Metrics{
		latencies: make([]time.Duration, latencyBufferSize),
	}
}

func (m *Metrics) TaskAdded() {
	m.TasksAdded.Add(1)
}

func (m *Metrics) TaskDispatched() {
	m.TasksDispatched.Add(1)
}

func (m *Metrics) RecordLatency(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.latencies[m.latencyIndex] = d
	m.latencyIndex = (m.latencyIndex + 1) % latencyBufferSize
}

func (m *Metrics) GetLatencies() []time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]time.Duration, latencyBufferSize)
	copy(result, m.latencies)
	return result
}
