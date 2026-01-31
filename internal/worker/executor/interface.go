package executor

import (
	"context"
	"encoding/json"
	"time"
)

type Executor interface {
	Execute(ctx context.Context, req *ExecuteRequest) (*ExecuteResponse, error)
	NodeType() string
}

type ExecuteRequest struct {
	NodeType string
	NodeID   string
	Config   json.RawMessage
	Input    json.RawMessage
	Attempt  int32
	Timeout  time.Duration
}

type ExecuteResponse struct {
	Output   json.RawMessage
	Error    *ExecutionError
	Logs     []LogEntry
	Duration time.Duration
}

type ExecutionError struct {
	Message    string
	Type       string // RETRYABLE, NON_RETRYABLE, TIMEOUT
	StackTrace string
}

type LogEntry struct {
	Timestamp time.Time
	Level     string
	Message   string
}

const (
	ErrorTypeRetryable    = "RETRYABLE"
	ErrorTypeNonRetryable = "NON_RETRYABLE"
	ErrorTypeTimeout      = "TIMEOUT"
)
