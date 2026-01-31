package executor

import (
	"context"
	"fmt"
	"sync"
)

// Registry manages all available node executors
type Registry struct {
	executors map[string]Executor
	mu        sync.RWMutex
}

// NewRegistry creates a new executor registry
func NewRegistry() *Registry {
	return &Registry{
		executors: make(map[string]Executor),
	}
}

// Register registers an executor for a node type
func (r *Registry) Register(executor Executor) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	nodeType := executor.NodeType()
	if _, exists := r.executors[nodeType]; exists {
		return fmt.Errorf("executor for node type '%s' is already registered", nodeType)
	}

	r.executors[nodeType] = executor
	return nil
}

// MustRegister registers an executor, panicking on error
func (r *Registry) MustRegister(executor Executor) {
	if err := r.Register(executor); err != nil {
		panic(err)
	}
}

// Get retrieves an executor by node type
func (r *Registry) Get(nodeType string) (Executor, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	executor, exists := r.executors[nodeType]
	return executor, exists
}

// Execute executes a request using the appropriate executor
func (r *Registry) Execute(ctx context.Context, req *ExecuteRequest) (*ExecuteResponse, error) {
	executor, exists := r.Get(req.NodeType)
	if !exists {
		return &ExecuteResponse{
			Error: &ExecutionError{
				Message: fmt.Sprintf("no executor found for node type: %s", req.NodeType),
				Type:    ErrorTypeNonRetryable,
			},
		}, nil
	}

	return executor.Execute(ctx, req)
}

// NodeTypes returns all registered node types
func (r *Registry) NodeTypes() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	types := make([]string, 0, len(r.executors))
	for nodeType := range r.executors {
		types = append(types, nodeType)
	}
	return types
}

// Count returns the number of registered executors
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.executors)
}

// DefaultRegistry is the global default registry
var DefaultRegistry = NewRegistry()

// DefaultRegistryInit initializes the default registry with all built-in executors
func DefaultRegistryInit() *Registry {
	registry := NewRegistry()

	// Register all built-in executors
	registry.MustRegister(NewHTTPExecutor())
	registry.MustRegister(NewCodeExecutor())
	registry.MustRegister(NewEmailExecutor())
	registry.MustRegister(NewConditionExecutor())
	registry.MustRegister(NewSlackExecutor())
	registry.MustRegister(NewDelayExecutor())
	registry.MustRegister(NewDatabaseExecutor())
	registry.MustRegister(NewAIExecutor())
	registry.MustRegister(NewWebhookExecutor())
	registry.MustRegister(NewTransformExecutor())
	registry.MustRegister(NewLoopExecutor())
	registry.MustRegister(NewDiscordExecutor())
	registry.MustRegister(NewTwilioExecutor())
	registry.MustRegister(NewStorageExecutor())

	return registry
}

// TransformExecutor handles data transformation nodes
type TransformExecutor struct{}

// TransformConfig represents the configuration for a transform node
type TransformConfig struct {
	// Transformation type
	Type string `json:"type"` // map, filter, reduce, pick, omit, merge, flatten, group

	// For map/filter/reduce operations
	Expression string `json:"expression"`

	// For pick/omit
	Fields []string `json:"fields"`

	// For merge
	Sources []string `json:"sources"`

	// Input data (if not provided, uses req.Input)
	Data interface{} `json:"data"`
}

// NewTransformExecutor creates a new transform executor
func NewTransformExecutor() *TransformExecutor {
	return &TransformExecutor{}
}

func (e *TransformExecutor) NodeType() string {
	return "transform"
}

func (e *TransformExecutor) Execute(ctx context.Context, req *ExecuteRequest) (*ExecuteResponse, error) {
	// TODO: Implement data transformation logic
	return &ExecuteResponse{
		Output: req.Input, // Pass through for now
	}, nil
}

// LoopExecutor handles loop/iteration nodes
type LoopExecutor struct{}

// LoopConfig represents the configuration for a loop node
type LoopConfig struct {
	// Loop type
	Type string `json:"type"` // forEach, while, repeat, parallel

	// For forEach
	Collection string `json:"collection"` // JSONPath to collection
	ItemVar    string `json:"item_var"`   // Variable name for current item
	IndexVar   string `json:"index_var"`  // Variable name for index

	// For while
	Condition string `json:"condition"`

	// For repeat
	Count int `json:"count"`

	// For parallel
	MaxConcurrency int `json:"max_concurrency"`

	// Nested actions (node IDs to execute in loop)
	Actions []string `json:"actions"`
}

// NewLoopExecutor creates a new loop executor
func NewLoopExecutor() *LoopExecutor {
	return &LoopExecutor{}
}

func (e *LoopExecutor) NodeType() string {
	return "loop"
}

func (e *LoopExecutor) Execute(ctx context.Context, req *ExecuteRequest) (*ExecuteResponse, error) {
	// TODO: Implement loop logic
	// This would typically be handled by the workflow engine, not executed directly
	return &ExecuteResponse{
		Output: req.Input,
	}, nil
}
