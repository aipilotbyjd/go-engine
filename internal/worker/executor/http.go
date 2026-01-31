package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type HTTPExecutor struct {
	client *http.Client
}

type HTTPConfig struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    json.RawMessage   `json:"body"`
	Timeout int               `json:"timeout"`
}

type HTTPResponse struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       json.RawMessage   `json:"body"`
}

// NewHTTPExecutor creates a new HTTP executor with connection pooling
func NewHTTPExecutor() *HTTPExecutor {
	// Configure transport with connection pooling for better performance
	transport := &http.Transport{
		MaxIdleConns:        100,              // Max idle connections across all hosts
		MaxIdleConnsPerHost: 20,               // Max idle connections per host
		MaxConnsPerHost:     50,               // Max total connections per host
		IdleConnTimeout:     90 * time.Second, // How long idle connections stay in pool
		DisableCompression:  false,            // Enable compression
		ForceAttemptHTTP2:   true,             // Prefer HTTP/2 when available
	}

	return &HTTPExecutor{
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
	}
}

func (e *HTTPExecutor) NodeType() string {
	return "http"
}

func (e *HTTPExecutor) Execute(ctx context.Context, req *ExecuteRequest) (*ExecuteResponse, error) {
	start := time.Now()
	logs := make([]LogEntry, 0)

	logs = append(logs, LogEntry{
		Timestamp: time.Now(),
		Level:     "INFO",
		Message:   fmt.Sprintf("Starting HTTP execution for node %s", req.NodeID),
	})

	var config HTTPConfig
	if err := json.Unmarshal(req.Config, &config); err != nil {
		return &ExecuteResponse{
			Error: &ExecutionError{
				Message: fmt.Sprintf("failed to parse HTTP config: %v", err),
				Type:    ErrorTypeNonRetryable,
			},
			Logs:     logs,
			Duration: time.Since(start),
		}, nil
	}

	if config.Method == "" {
		config.Method = "GET"
	}

	if config.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(config.Timeout)*time.Second)
		defer cancel()
	}

	var bodyReader io.Reader
	if len(config.Body) > 0 {
		bodyReader = bytes.NewReader(config.Body)
	}

	httpReq, err := http.NewRequestWithContext(ctx, config.Method, config.URL, bodyReader)
	if err != nil {
		return &ExecuteResponse{
			Error: &ExecutionError{
				Message: fmt.Sprintf("failed to create HTTP request: %v", err),
				Type:    ErrorTypeNonRetryable,
			},
			Logs:     logs,
			Duration: time.Since(start),
		}, nil
	}

	for key, value := range config.Headers {
		httpReq.Header.Set(key, value)
	}

	logs = append(logs, LogEntry{
		Timestamp: time.Now(),
		Level:     "INFO",
		Message:   fmt.Sprintf("Sending %s request to %s", config.Method, config.URL),
	})

	resp, err := e.client.Do(httpReq)
	if err != nil {
		errorType := ErrorTypeRetryable
		if ctx.Err() == context.DeadlineExceeded {
			errorType = ErrorTypeTimeout
		}
		return &ExecuteResponse{
			Error: &ExecutionError{
				Message: fmt.Sprintf("HTTP request failed: %v", err),
				Type:    errorType,
			},
			Logs:     logs,
			Duration: time.Since(start),
		}, nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &ExecuteResponse{
			Error: &ExecutionError{
				Message: fmt.Sprintf("failed to read response body: %v", err),
				Type:    ErrorTypeRetryable,
			},
			Logs:     logs,
			Duration: time.Since(start),
		}, nil
	}

	logs = append(logs, LogEntry{
		Timestamp: time.Now(),
		Level:     "INFO",
		Message:   fmt.Sprintf("Received response with status %d", resp.StatusCode),
	})

	headers := make(map[string]string)
	for key := range resp.Header {
		headers[key] = resp.Header.Get(key)
	}

	httpResp := HTTPResponse{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       body,
	}

	output, err := json.Marshal(httpResp)
	if err != nil {
		return &ExecuteResponse{
			Error: &ExecutionError{
				Message: fmt.Sprintf("failed to marshal response: %v", err),
				Type:    ErrorTypeNonRetryable,
			},
			Logs:     logs,
			Duration: time.Since(start),
		}, nil
	}

	if resp.StatusCode >= 500 {
		return &ExecuteResponse{
			Output: output,
			Error: &ExecutionError{
				Message: fmt.Sprintf("server error: status %d", resp.StatusCode),
				Type:    ErrorTypeRetryable,
			},
			Logs:     logs,
			Duration: time.Since(start),
		}, nil
	}

	if resp.StatusCode >= 400 {
		return &ExecuteResponse{
			Output: output,
			Error: &ExecutionError{
				Message: fmt.Sprintf("client error: status %d", resp.StatusCode),
				Type:    ErrorTypeNonRetryable,
			},
			Logs:     logs,
			Duration: time.Since(start),
		}, nil
	}

	return &ExecuteResponse{
		Output:   output,
		Logs:     logs,
		Duration: time.Since(start),
	}, nil
}
