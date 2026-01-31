package shard

import (
	"hash/fnv"
	"sync"

	"github.com/linkflow/engine/internal/history"
)

type ShardStatus int

const (
	ShardStatusUnknown ShardStatus = iota
	ShardStatusOwned
	ShardStatusTransferring
	ShardStatusStopped
)

type Shard struct {
	ShardID int32
	Status  ShardStatus
	mu      sync.RWMutex
}

func NewShard(shardID int32) *Shard {
	return &Shard{
		ShardID: shardID,
		Status:  ShardStatusOwned,
	}
}

func (s *Shard) GetID() int32 {
	return s.ShardID
}

func (s *Shard) GetStatus() ShardStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Status
}

func (s *Shard) SetStatus(status ShardStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Status = status
}

type Controller struct {
	numShards int
	shards    map[int32]*Shard
	mu        sync.RWMutex
}

func NewController(numShards int) *Controller {
	if numShards <= 0 {
		numShards = 16
	}
	return &Controller{
		numShards: numShards,
		shards:    make(map[int32]*Shard),
	}
}

func (c *Controller) GetShard(shardID int32) (*Shard, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	shard, exists := c.shards[shardID]
	return shard, exists
}

func (c *Controller) GetShardForExecution(key history.ExecutionKey) (*Shard, error) {
	shardID := c.GetShardIDForExecution(key)

	c.mu.Lock()
	defer c.mu.Unlock()

	shard, exists := c.shards[shardID]
	if !exists {
		shard = NewShard(shardID)
		c.shards[shardID] = shard
	}

	return shard, nil
}

func (c *Controller) GetShardIDForExecution(key history.ExecutionKey) int32 {
	h := fnv.New32a()
	h.Write([]byte(key.NamespaceID))
	h.Write([]byte(key.WorkflowID))
	hashValue := h.Sum32()
	return int32(hashValue % uint32(c.numShards))
}

func (c *Controller) AcquireShard(shardID int32) (*Shard, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	shard, exists := c.shards[shardID]
	if exists {
		return shard, nil
	}

	shard = NewShard(shardID)
	c.shards[shardID] = shard
	return shard, nil
}

func (c *Controller) ReleaseShard(shardID int32) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	shard, exists := c.shards[shardID]
	if !exists {
		return nil
	}

	shard.SetStatus(ShardStatusStopped)
	delete(c.shards, shardID)
	return nil
}

func (c *Controller) GetAllShards() []*Shard {
	c.mu.RLock()
	defer c.mu.RUnlock()

	shards := make([]*Shard, 0, len(c.shards))
	for _, shard := range c.shards {
		shards = append(shards, shard)
	}
	return shards
}

func (c *Controller) GetNumShards() int {
	return c.numShards
}

func (c *Controller) GetOwnedShardCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	count := 0
	for _, shard := range c.shards {
		if shard.GetStatus() == ShardStatusOwned {
			count++
		}
	}
	return count
}

func (c *Controller) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for shardID, shard := range c.shards {
		shard.SetStatus(ShardStatusStopped)
		delete(c.shards, shardID)
	}
}
