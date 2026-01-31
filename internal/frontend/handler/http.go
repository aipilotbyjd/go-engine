package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/linkflow/engine/internal/frontend"
)

// HTTPHandler provides HTTP endpoints for the Frontend service
// Laravel will call these endpoints to interact with the engine
type HTTPHandler struct {
	service *frontend.Service
	logger  *slog.Logger
}

// NewHTTPHandler creates a new HTTP handler
func NewHTTPHandler(service *frontend.Service, logger *slog.Logger) *HTTPHandler {
	return &HTTPHandler{
		service: service,
		logger:  logger,
	}
}

// RegisterRoutes registers all HTTP routes
func (h *HTTPHandler) RegisterRoutes(mux *http.ServeMux) {
	// Workflow execution endpoints
	mux.HandleFunc("POST /api/v1/workflows/execute", h.StartWorkflow)
	mux.HandleFunc("GET /api/v1/workspaces/{workspace_id}/executions/{execution_id}", h.GetExecution)
	mux.HandleFunc("POST /api/v1/workspaces/{workspace_id}/executions/{execution_id}/cancel", h.CancelExecution)
	mux.HandleFunc("POST /api/v1/workspaces/{workspace_id}/executions/{execution_id}/retry", h.RetryExecution)
	mux.HandleFunc("POST /api/v1/workspaces/{workspace_id}/executions/{execution_id}/signal", h.SendSignal)

	// List executions
	mux.HandleFunc("GET /api/v1/workspaces/{workspace_id}/executions", h.ListExecutions)

	// Health check
	mux.HandleFunc("GET /health", h.Health)
	mux.HandleFunc("GET /ready", h.Ready)
}

// StartWorkflowRequest is the request to start a workflow
type StartWorkflowRequest struct {
	WorkspaceID    string                 `json:"workspace_id"`
	WorkflowID     string                 `json:"workflow_id"`
	ExecutionID    string                 `json:"execution_id,omitempty"`
	IdempotencyKey string                 `json:"idempotency_key,omitempty"`
	Input          map[string]interface{} `json:"input"`
	TaskQueue      string                 `json:"task_queue,omitempty"`
	Priority       int                    `json:"priority,omitempty"`
	CallbackURL    string                 `json:"callback_url,omitempty"`
}

// StartWorkflowResponse is the response from starting a workflow
type StartWorkflowResponse struct {
	ExecutionID string `json:"execution_id"`
	RunID       string `json:"run_id"`
	Started     bool   `json:"started"`
}

// StartWorkflow starts a new workflow execution
// POST /api/v1/workflows/execute
func (h *HTTPHandler) StartWorkflow(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req StartWorkflowRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body: "+err.Error())
		return
	}

	// Validate required fields
	if req.WorkspaceID == "" {
		h.writeError(w, http.StatusBadRequest, "workspace_id is required")
		return
	}
	if req.WorkflowID == "" {
		h.writeError(w, http.StatusBadRequest, "workflow_id is required")
		return
	}

	// Generate execution ID if not provided
	if req.ExecutionID == "" {
		req.ExecutionID = generateExecutionID()
	}

	// Start the workflow
	inputBytes, _ := json.Marshal(req.Input)
	frontendReq := &frontend.StartWorkflowExecutionRequest{
		Namespace:  req.WorkspaceID,
		WorkflowID: req.WorkflowID,
		TaskQueue:  req.TaskQueue,
		RequestID:  req.IdempotencyKey,
		Input:      inputBytes,
	}

	resp, err := h.service.StartWorkflowExecution(ctx, frontendReq)
	if err != nil {
		h.logger.Error("failed to start workflow",
			slog.String("workspace_id", req.WorkspaceID),
			slog.String("workflow_id", req.WorkflowID),
			slog.String("error", err.Error()),
		)
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.logger.Info("workflow started",
		slog.String("workspace_id", req.WorkspaceID),
		slog.String("workflow_id", req.WorkflowID),
		slog.String("execution_id", req.ExecutionID),
		slog.String("run_id", resp.RunID),
	)

	h.writeJSON(w, http.StatusOK, StartWorkflowResponse{
		ExecutionID: req.ExecutionID,
		RunID:       resp.RunID,
		Started:     true,
	})
}

// ExecutionInfo holds execution information
type ExecutionInfo struct {
	ExecutionID string                 `json:"execution_id"`
	WorkflowID  string                 `json:"workflow_id"`
	RunID       string                 `json:"run_id"`
	Status      string                 `json:"status"`
	StartedAt   time.Time              `json:"started_at"`
	FinishedAt  *time.Time             `json:"finished_at,omitempty"`
	Input       map[string]interface{} `json:"input"`
	Output      map[string]interface{} `json:"output,omitempty"`
	Error       string                 `json:"error,omitempty"`
}

// GetExecution gets the status of an execution
// GET /api/v1/workspaces/{workspace_id}/executions/{execution_id}
func (h *HTTPHandler) GetExecution(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	workspaceID := r.PathValue("workspace_id")
	executionID := r.PathValue("execution_id")

	req := &frontend.GetExecutionRequest{
		Namespace:  workspaceID,
		WorkflowID: executionID,
		RunID:      "",
	}

	resp, err := h.service.GetExecution(ctx, req)
	if err != nil {
		h.writeError(w, http.StatusNotFound, "Execution not found")
		return
	}

	info := ExecutionInfo{
		ExecutionID: executionID,
		WorkflowID:  resp.Execution.WorkflowID,
		RunID:       resp.Execution.RunID,
		Status:      statusToString(resp.Execution.Status),
		StartedAt:   resp.Execution.StartTime,
	}

	h.writeJSON(w, http.StatusOK, info)
}

// ListExecutions lists executions for a workspace
// GET /api/v1/workspaces/{workspace_id}/executions
func (h *HTTPHandler) ListExecutions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	workspaceID := r.PathValue("workspace_id")

	req := &frontend.ListExecutionsRequest{
		Namespace: workspaceID,
		PageSize:  100,
	}

	resp, err := h.service.ListExecutions(ctx, req)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"executions": resp.Executions,
		"has_more":   len(resp.NextPageToken) > 0,
	})
}

// CancelExecution cancels a running execution
// POST /api/v1/workspaces/{workspace_id}/executions/{execution_id}/cancel
func (h *HTTPHandler) CancelExecution(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	workspaceID := r.PathValue("workspace_id")
	executionID := r.PathValue("execution_id")

	var body struct {
		Reason string `json:"reason"`
	}
	json.NewDecoder(r.Body).Decode(&body)

	req := &frontend.TerminateWorkflowExecutionRequest{
		Namespace:  workspaceID,
		WorkflowID: executionID,
		Reason:     body.Reason,
	}

	if err := h.service.TerminateWorkflowExecution(ctx, req); err != nil {
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]string{"status": "canceled"})
}

// RetryExecution retries a failed execution
// POST /api/v1/workspaces/{workspace_id}/executions/{execution_id}/retry
func (h *HTTPHandler) RetryExecution(w http.ResponseWriter, r *http.Request) {
	// Placeholder - will be implemented
	h.writeJSON(w, http.StatusOK, map[string]string{"status": "retry_initiated"})
}

// SendSignal sends a signal to a running execution
// POST /api/v1/workspaces/{workspace_id}/executions/{execution_id}/signal
func (h *HTTPHandler) SendSignal(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	workspaceID := r.PathValue("workspace_id")
	executionID := r.PathValue("execution_id")

	var body struct {
		SignalName string      `json:"signal_name"`
		Data       interface{} `json:"data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	inputData, _ := json.Marshal(body.Data)

	req := &frontend.SignalWorkflowExecutionRequest{
		Namespace:  workspaceID,
		WorkflowID: executionID,
		SignalName: body.SignalName,
		Input:      inputData,
	}

	if err := h.service.SignalWorkflowExecution(ctx, req); err != nil {
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]string{"status": "signal_sent"})
}

// Health check endpoint
func (h *HTTPHandler) Health(w http.ResponseWriter, r *http.Request) {
	h.writeJSON(w, http.StatusOK, map[string]string{"status": "healthy"})
}

// Ready check endpoint
func (h *HTTPHandler) Ready(w http.ResponseWriter, r *http.Request) {
	h.writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// Helper functions

func (h *HTTPHandler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *HTTPHandler) writeError(w http.ResponseWriter, status int, message string) {
	h.writeJSON(w, status, map[string]string{"error": message})
}

func generateExecutionID() string {
	return "exec-" + randomString(16)
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[i%len(letters)]
	}
	return string(b)
}

func statusToString(status frontend.ExecutionStatus) string {
	switch status {
	case frontend.ExecutionStatusRunning:
		return "running"
	case frontend.ExecutionStatusCompleted:
		return "completed"
	case frontend.ExecutionStatusFailed:
		return "failed"
	case frontend.ExecutionStatusCanceled:
		return "canceled"
	case frontend.ExecutionStatusTerminated:
		return "terminated"
	case frontend.ExecutionStatusTimedOut:
		return "timed_out"
	default:
		return "pending"
	}
}
