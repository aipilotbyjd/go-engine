package callback

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// Client sends callbacks to Laravel when workflow events occur
type Client struct {
	httpClient *http.Client
	secretKey  string // Shared secret for signing callbacks
	logger     *slog.Logger
}

// Config holds callback client configuration
type Config struct {
	Timeout   time.Duration
	SecretKey string // Shared secret for HMAC signing
}

// DefaultConfig returns default callback config
func DefaultConfig() Config {
	return Config{
		Timeout:   10 * time.Second,
		SecretKey: "", // Should be set from environment
	}
}

// NewClient creates a new callback client
func NewClient(cfg Config, logger *slog.Logger) *Client {
	if logger == nil {
		logger = slog.Default()
	}
	return &Client{
		httpClient: &http.Client{Timeout: cfg.Timeout},
		secretKey:  cfg.SecretKey,
		logger:     logger,
	}
}

// Event types for callbacks
type EventType string

const (
	EventTypeExecutionStarted   EventType = "execution.started"
	EventTypeExecutionCompleted EventType = "execution.completed"
	EventTypeExecutionFailed    EventType = "execution.failed"
	EventTypeExecutionCanceled  EventType = "execution.canceled"
	EventTypeNodeStarted        EventType = "node.started"
	EventTypeNodeCompleted      EventType = "node.completed"
	EventTypeNodeFailed         EventType = "node.failed"
)

// CallbackPayload is the payload sent to Laravel
type CallbackPayload struct {
	Event       EventType              `json:"event"`
	Timestamp   time.Time              `json:"timestamp"`
	WorkspaceID string                 `json:"workspace_id"`
	WorkflowID  string                 `json:"workflow_id"`
	ExecutionID string                 `json:"execution_id"`
	RunID       string                 `json:"run_id"`
	Data        map[string]interface{} `json:"data,omitempty"`
}

// ExecutionStartedData is the data for execution.started event
type ExecutionStartedData struct {
	TriggerType string                 `json:"trigger_type"`
	Input       map[string]interface{} `json:"input"`
}

// ExecutionCompletedData is the data for execution.completed event
type ExecutionCompletedData struct {
	Duration time.Duration          `json:"duration_ms"`
	Output   map[string]interface{} `json:"output"`
}

// ExecutionFailedData is the data for execution.failed event
type ExecutionFailedData struct {
	Duration   time.Duration `json:"duration_ms"`
	ErrorCode  string        `json:"error_code"`
	ErrorMsg   string        `json:"error_message"`
	FailedNode string        `json:"failed_node,omitempty"`
	Attempt    int           `json:"attempt"`
	Retryable  bool          `json:"retryable"`
}

// NodeCompletedData is the data for node.completed event
type NodeCompletedData struct {
	NodeID   string                 `json:"node_id"`
	NodeType string                 `json:"node_type"`
	NodeName string                 `json:"node_name"`
	Duration time.Duration          `json:"duration_ms"`
	Output   map[string]interface{} `json:"output"`
}

// NodeFailedData is the data for node.failed event
type NodeFailedData struct {
	NodeID     string        `json:"node_id"`
	NodeType   string        `json:"node_type"`
	NodeName   string        `json:"node_name"`
	Duration   time.Duration `json:"duration_ms"`
	ErrorCode  string        `json:"error_code"`
	ErrorMsg   string        `json:"error_message"`
	Attempt    int           `json:"attempt"`
	MaxRetries int           `json:"max_retries"`
	WillRetry  bool          `json:"will_retry"`
}

// Send sends a callback to the specified URL
func (c *Client) Send(ctx context.Context, callbackURL string, payload *CallbackPayload) error {
	if callbackURL == "" {
		return nil // No callback URL configured
	}

	// Serialize payload
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to serialize callback payload: %w", err)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", callbackURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create callback request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-LinkFlow-Event", string(payload.Event))
	req.Header.Set("X-LinkFlow-Timestamp", payload.Timestamp.Format(time.RFC3339))

	// Sign the request if secret key is set
	if c.secretKey != "" {
		signature := c.sign(body)
		req.Header.Set("X-LinkFlow-Signature", signature)
	}

	// Send request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Error("callback request failed",
			slog.String("url", callbackURL),
			slog.String("event", string(payload.Event)),
			slog.String("error", err.Error()),
		)
		return fmt.Errorf("callback request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check response
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		c.logger.Error("callback returned error",
			slog.String("url", callbackURL),
			slog.Int("status", resp.StatusCode),
			slog.String("body", string(body)),
		)
		return fmt.Errorf("callback returned status %d", resp.StatusCode)
	}

	c.logger.Info("callback sent successfully",
		slog.String("url", callbackURL),
		slog.String("event", string(payload.Event)),
		slog.String("execution_id", payload.ExecutionID),
	)

	return nil
}

// sign generates HMAC-SHA256 signature for the payload
func (c *Client) sign(payload []byte) string {
	h := hmac.New(sha256.New, []byte(c.secretKey))
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))
}

// NotifyExecutionStarted notifies Laravel that an execution started
func (c *Client) NotifyExecutionStarted(ctx context.Context, callbackURL string, workspaceID, workflowID, executionID, runID string, input map[string]interface{}) error {
	return c.Send(ctx, callbackURL, &CallbackPayload{
		Event:       EventTypeExecutionStarted,
		Timestamp:   time.Now().UTC(),
		WorkspaceID: workspaceID,
		WorkflowID:  workflowID,
		ExecutionID: executionID,
		RunID:       runID,
		Data: map[string]interface{}{
			"input": input,
		},
	})
}

// NotifyExecutionCompleted notifies Laravel that an execution completed
func (c *Client) NotifyExecutionCompleted(ctx context.Context, callbackURL string, workspaceID, workflowID, executionID, runID string, output map[string]interface{}, duration time.Duration) error {
	return c.Send(ctx, callbackURL, &CallbackPayload{
		Event:       EventTypeExecutionCompleted,
		Timestamp:   time.Now().UTC(),
		WorkspaceID: workspaceID,
		WorkflowID:  workflowID,
		ExecutionID: executionID,
		RunID:       runID,
		Data: map[string]interface{}{
			"output":      output,
			"duration_ms": duration.Milliseconds(),
		},
	})
}

// NotifyExecutionFailed notifies Laravel that an execution failed
func (c *Client) NotifyExecutionFailed(ctx context.Context, callbackURL string, workspaceID, workflowID, executionID, runID string, errorCode, errorMsg, failedNode string) error {
	return c.Send(ctx, callbackURL, &CallbackPayload{
		Event:       EventTypeExecutionFailed,
		Timestamp:   time.Now().UTC(),
		WorkspaceID: workspaceID,
		WorkflowID:  workflowID,
		ExecutionID: executionID,
		RunID:       runID,
		Data: map[string]interface{}{
			"error_code":    errorCode,
			"error_message": errorMsg,
			"failed_node":   failedNode,
		},
	})
}

// NotifyNodeCompleted notifies Laravel that a node completed
func (c *Client) NotifyNodeCompleted(ctx context.Context, callbackURL string, workspaceID, workflowID, executionID, runID, nodeID, nodeType, nodeName string, output map[string]interface{}, duration time.Duration) error {
	return c.Send(ctx, callbackURL, &CallbackPayload{
		Event:       EventTypeNodeCompleted,
		Timestamp:   time.Now().UTC(),
		WorkspaceID: workspaceID,
		WorkflowID:  workflowID,
		ExecutionID: executionID,
		RunID:       runID,
		Data: map[string]interface{}{
			"node_id":     nodeID,
			"node_type":   nodeType,
			"node_name":   nodeName,
			"output":      output,
			"duration_ms": duration.Milliseconds(),
		},
	})
}
