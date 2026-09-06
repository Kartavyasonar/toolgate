package audit
import "crypto/sha256"
import "encoding/hex"

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

const DefaultLogPath = "audit.log"

type AuditEvent struct {
	Timestamp          time.Time `json:"timestamp"`
	RequestID          string    `json:"request_id"`
	Method             string    `json:"method"`
	ToolName           string    `json:"tool_name"`
	Action             string    `json:"action"`
	Reason             string    `json:"reason"`
	PolicyMode         string    `json:"policy_mode"`
	ClientAddress      string    `json:"client_address"`
	PayloadSHA256      string    `json:"payload_sha256"`
	RedactedFieldCount int       `json:"redacted_field_count"`
}

type Logger struct {
	Path string

	mu     sync.Mutex
	file   *os.File
	closed bool
}

func NewLogger(path string) (*Logger, error) {
	if path == "" {
		path = DefaultLogPath
	}
	logger := &Logger{Path: path}
	logger.mu.Lock()
	defer logger.mu.Unlock()
	if err := logger.ensureOpenLocked(); err != nil {
		return nil, err
	}
	return logger, nil
}

func (l *Logger) Log(event AuditEvent) error {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if event.RequestID == "" {
		id, err := newRequestID()
		if err != nil {
			return err
		}
		event.RequestID = id
	}

	line, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal audit event: %w", err)
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.ensureOpenLocked(); err != nil {
		return err
	}
	if _, err := l.file.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("write audit event: %w", err)
	}
	return nil
}

func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	if err != nil {
		return fmt.Errorf("close audit log: %w", err)
	}
	return nil
}

func (l *Logger) ensureOpenLocked() error {
	if l.closed {
		return fmt.Errorf("audit logger is closed")
	}
	if l.file != nil {
		return nil
	}
	path := l.Path
	if path == "" {
		path = DefaultLogPath
		l.Path = path
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open audit log %s: %w", path, err)
	}
	l.file = file
	return nil
}

func newRequestID() (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return "", fmt.Errorf("generate request id: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}
func HashPayload(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}