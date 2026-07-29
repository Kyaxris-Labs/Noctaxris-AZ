package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Event is a lab audit / activity-log shaped record.
type Event struct {
	InsertID       string    `json:"insertId"`
	Timestamp      time.Time `json:"timestamp"`
	PrincipalID    string    `json:"principalId,omitempty"`
	Operation      string    `json:"operation,omitempty"`
	ResourceID     string    `json:"resourceId,omitempty"`
	StatusCode     int       `json:"statusCode,omitempty"`
	RequestID      string    `json:"requestId,omitempty"`
	Message        string    `json:"message,omitempty"`
}

// Writer appends JSON lines to audit.jsonl.
type Writer struct {
	path string
	file *os.File
	mu   sync.Mutex
}

// NewWriter opens or creates dir/audit.jsonl.
func NewWriter(dir string) (*Writer, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("audit: create dir: %w", err)
	}
	path := filepath.Join(dir, "audit.jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open events file: %w", err)
	}
	_ = f.Chmod(0o600)
	return &Writer{path: path, file: f}, nil
}

// Write appends one JSON event line.
func (w *Writer) Write(ctx context.Context, ev Event) error {
	if w == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	_, err = w.file.Write(append(b, '\n'))
	return err
}

// Close closes the underlying file.
func (w *Writer) Close() error {
	if w == nil || w.file == nil {
		return nil
	}
	return w.file.Close()
}
