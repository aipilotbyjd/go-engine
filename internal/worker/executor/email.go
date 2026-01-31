package executor

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html/template"
	"net/smtp"
	"strings"
	"time"
)

// EmailExecutor handles email sending via SMTP
type EmailExecutor struct {
	defaultHost string
	defaultPort int
	defaultFrom string
}

// EmailConfig represents the configuration for an email node
type EmailConfig struct {
	// SMTP Configuration
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	UseTLS   bool   `json:"use_tls"`

	// Email fields
	From     string   `json:"from"`
	To       []string `json:"to"`
	Cc       []string `json:"cc"`
	Bcc      []string `json:"bcc"`
	Subject  string   `json:"subject"`
	Body     string   `json:"body"`
	BodyHTML string   `json:"body_html"`
	ReplyTo  string   `json:"reply_to"`

	// Template support
	UseTemplate  bool                   `json:"use_template"`
	TemplateVars map[string]interface{} `json:"template_vars"`
}

// EmailResponse represents the result of an email send operation
type EmailResponse struct {
	Success    bool     `json:"success"`
	MessageID  string   `json:"message_id"`
	Recipients []string `json:"recipients"`
	Timestamp  string   `json:"timestamp"`
}

// NewEmailExecutor creates a new email executor
func NewEmailExecutor() *EmailExecutor {
	return &EmailExecutor{
		defaultHost: "localhost",
		defaultPort: 25,
	}
}

// WithDefaults sets default SMTP configuration
func (e *EmailExecutor) WithDefaults(host string, port int, from string) *EmailExecutor {
	e.defaultHost = host
	e.defaultPort = port
	e.defaultFrom = from
	return e
}

func (e *EmailExecutor) NodeType() string {
	return "email"
}

func (e *EmailExecutor) Execute(ctx context.Context, req *ExecuteRequest) (*ExecuteResponse, error) {
	start := time.Now()
	logs := make([]LogEntry, 0)

	logs = append(logs, LogEntry{
		Timestamp: time.Now(),
		Level:     "INFO",
		Message:   fmt.Sprintf("Starting email execution for node %s", req.NodeID),
	})

	var config EmailConfig
	if err := json.Unmarshal(req.Config, &config); err != nil {
		return &ExecuteResponse{
			Error: &ExecutionError{
				Message: fmt.Sprintf("failed to parse email config: %v", err),
				Type:    ErrorTypeNonRetryable,
			},
			Logs:     logs,
			Duration: time.Since(start),
		}, nil
	}

	// Apply defaults
	if config.Host == "" {
		config.Host = e.defaultHost
	}
	if config.Port == 0 {
		config.Port = e.defaultPort
	}
	if config.From == "" {
		config.From = e.defaultFrom
	}

	// Validate required fields
	if len(config.To) == 0 {
		return &ExecuteResponse{
			Error: &ExecutionError{
				Message: "at least one recipient is required",
				Type:    ErrorTypeNonRetryable,
			},
			Logs:     logs,
			Duration: time.Since(start),
		}, nil
	}

	if config.Subject == "" {
		return &ExecuteResponse{
			Error: &ExecutionError{
				Message: "email subject is required",
				Type:    ErrorTypeNonRetryable,
			},
			Logs:     logs,
			Duration: time.Since(start),
		}, nil
	}

	// Process templates if enabled
	body := config.Body
	bodyHTML := config.BodyHTML
	subject := config.Subject

	if config.UseTemplate && config.TemplateVars != nil {
		var err error
		subject, err = processTemplate("subject", subject, config.TemplateVars)
		if err != nil {
			logs = append(logs, LogEntry{
				Timestamp: time.Now(),
				Level:     "WARN",
				Message:   fmt.Sprintf("Failed to process subject template: %v", err),
			})
		}

		if body != "" {
			body, err = processTemplate("body", body, config.TemplateVars)
			if err != nil {
				logs = append(logs, LogEntry{
					Timestamp: time.Now(),
					Level:     "WARN",
					Message:   fmt.Sprintf("Failed to process body template: %v", err),
				})
			}
		}

		if bodyHTML != "" {
			bodyHTML, err = processTemplate("bodyHTML", bodyHTML, config.TemplateVars)
			if err != nil {
				logs = append(logs, LogEntry{
					Timestamp: time.Now(),
					Level:     "WARN",
					Message:   fmt.Sprintf("Failed to process HTML body template: %v", err),
				})
			}
		}
	}

	// Build the email message
	message := buildEmailMessage(config.From, config.To, config.Cc, subject, body, bodyHTML, config.ReplyTo)

	// All recipients (To + Cc + Bcc)
	allRecipients := make([]string, 0, len(config.To)+len(config.Cc)+len(config.Bcc))
	allRecipients = append(allRecipients, config.To...)
	allRecipients = append(allRecipients, config.Cc...)
	allRecipients = append(allRecipients, config.Bcc...)

	logs = append(logs, LogEntry{
		Timestamp: time.Now(),
		Level:     "INFO",
		Message:   fmt.Sprintf("Sending email to %d recipients via %s:%d", len(allRecipients), config.Host, config.Port),
	})

	// Send the email
	addr := fmt.Sprintf("%s:%d", config.Host, config.Port)
	var auth smtp.Auth
	if config.Username != "" && config.Password != "" {
		auth = smtp.PlainAuth("", config.Username, config.Password, config.Host)
	}

	var sendErr error
	if config.UseTLS {
		sendErr = sendMailWithTLS(addr, auth, config.From, allRecipients, message)
	} else {
		sendErr = smtp.SendMail(addr, auth, config.From, allRecipients, message)
	}

	if sendErr != nil {
		errorType := ErrorTypeRetryable
		// Non-retryable errors
		if strings.Contains(sendErr.Error(), "authentication") ||
			strings.Contains(sendErr.Error(), "invalid") ||
			strings.Contains(sendErr.Error(), "not accepted") {
			errorType = ErrorTypeNonRetryable
		}

		return &ExecuteResponse{
			Error: &ExecutionError{
				Message: fmt.Sprintf("failed to send email: %v", sendErr),
				Type:    errorType,
			},
			Logs:     logs,
			Duration: time.Since(start),
		}, nil
	}

	logs = append(logs, LogEntry{
		Timestamp: time.Now(),
		Level:     "INFO",
		Message:   "Email sent successfully",
	})

	// Generate a pseudo message ID
	messageID := fmt.Sprintf("<%d.%s@linkflow>", time.Now().UnixNano(), req.NodeID)

	response := EmailResponse{
		Success:    true,
		MessageID:  messageID,
		Recipients: allRecipients,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
	}

	output, err := json.Marshal(response)
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

	return &ExecuteResponse{
		Output:   output,
		Logs:     logs,
		Duration: time.Since(start),
	}, nil
}

func processTemplate(name, text string, vars map[string]interface{}) (string, error) {
	tmpl, err := template.New(name).Parse(text)
	if err != nil {
		return text, err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, vars); err != nil {
		return text, err
	}

	return buf.String(), nil
}

func buildEmailMessage(from string, to, cc []string, subject, body, bodyHTML, replyTo string) []byte {
	var buf bytes.Buffer

	buf.WriteString(fmt.Sprintf("From: %s\r\n", from))
	buf.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(to, ", ")))
	if len(cc) > 0 {
		buf.WriteString(fmt.Sprintf("Cc: %s\r\n", strings.Join(cc, ", ")))
	}
	if replyTo != "" {
		buf.WriteString(fmt.Sprintf("Reply-To: %s\r\n", replyTo))
	}
	buf.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	buf.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z)))
	buf.WriteString("MIME-Version: 1.0\r\n")

	if bodyHTML != "" {
		// Multipart message with both plain text and HTML
		boundary := fmt.Sprintf("boundary-%d", time.Now().UnixNano())
		buf.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=\"%s\"\r\n", boundary))
		buf.WriteString("\r\n")

		if body != "" {
			buf.WriteString(fmt.Sprintf("--%s\r\n", boundary))
			buf.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n")
			buf.WriteString("\r\n")
			buf.WriteString(body)
			buf.WriteString("\r\n")
		}

		buf.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		buf.WriteString("Content-Type: text/html; charset=\"utf-8\"\r\n")
		buf.WriteString("\r\n")
		buf.WriteString(bodyHTML)
		buf.WriteString("\r\n")

		buf.WriteString(fmt.Sprintf("--%s--\r\n", boundary))
	} else {
		buf.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n")
		buf.WriteString("\r\n")
		buf.WriteString(body)
	}

	return buf.Bytes()
}

func sendMailWithTLS(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
	tlsConfig := &tls.Config{
		ServerName: strings.Split(addr, ":")[0],
	}

	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return err
	}
	defer conn.Close()

	host := strings.Split(addr, ":")[0]
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer client.Close()

	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return err
		}
	}

	if err := client.Mail(from); err != nil {
		return err
	}

	for _, recipient := range to {
		if err := client.Rcpt(recipient); err != nil {
			return err
		}
	}

	w, err := client.Data()
	if err != nil {
		return err
	}

	if _, err := w.Write(msg); err != nil {
		return err
	}

	if err := w.Close(); err != nil {
		return err
	}

	return client.Quit()
}
