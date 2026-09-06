package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLog(t *testing.T) {
	fixed := time.Date(2026, 9, 6, 11, 32, 1, 123456789, time.UTC)

	tests := []struct {
		name  string
		event AuditEvent
		check func(t *testing.T, raw string, got AuditEvent)
	}{
		{
			name: "writes parseable json line with rfc3339nano timestamp",
			event: AuditEvent{
				Timestamp:          fixed,
				RequestID:          "11111111-2222-4333-8444-555555555555",
				Method:             "tools/call",
				ToolName:           "safe_search",
				Action:             "allow",
				Reason:             "Search is permitted",
				PolicyMode:         "monitor",
				ClientAddress:      "127.0.0.1:54321",
				PayloadSHA256:      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				RedactedFieldCount: 2,
			},
			check: func(t *testing.T, raw string, got AuditEvent) {
				if !strings.HasSuffix(raw, "\n") {
					t.Fatal("line is missing trailing newline")
				}
				if strings.Count(raw, "\n") != 1 {
					t.Fatalf("expected exactly one newline, got %q", raw)
				}
				if strings.Contains(strings.ToLower(raw), "password") || strings.Contains(raw, `"payload"`) {
					t.Fatalf("audit line appears to contain a payload or secret: %s", raw)
				}

				var envelope map[string]any
				if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &envelope); err != nil {
					t.Fatalf("envelope json: %v", err)
				}
				ts, ok := envelope["timestamp"].(string)
				if !ok {
					t.Fatalf("timestamp is not a string: %#v", envelope["timestamp"])
				}
				parsed, err := time.Parse(time.RFC3339Nano, ts)
				if err != nil {
					t.Fatalf("timestamp %q is not RFC3339Nano: %v", ts, err)
				}
				if !parsed.Equal(fixed) {
					t.Fatalf("timestamp = %v, want %v", parsed, fixed)
				}
				if !strings.Contains(ts, "2026-09-06T11:32:01.123456789Z") {
					t.Fatalf("timestamp %q missing full nanosecond RFC3339 form", ts)
				}

				if got.RequestID != "11111111-2222-4333-8444-555555555555" {
					t.Errorf("RequestID = %q", got.RequestID)
				}
				if got.Method != "tools/call" || got.ToolName != "safe_search" {
					t.Errorf("method/tool = %q %q", got.Method, got.ToolName)
				}
				if got.Action != "allow" || got.PolicyMode != "monitor" {
					t.Errorf("action/mode = %q %q", got.Action, got.PolicyMode)
				}
				if got.PayloadSHA256 == "" {
					t.Error("PayloadSHA256 is empty")
				}
				if got.RedactedFieldCount != 2 {
					t.Errorf("RedactedFieldCount = %d", got.RedactedFieldCount)
				}
			},
		},
		{
			name: "empty request id and timestamp are filled",
			event: AuditEvent{
				Method:        "tools/list",
				Action:        "allow",
				PolicyMode:    "enforce",
				PayloadSHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			},
			check: func(t *testing.T, raw string, got AuditEvent) {
				if got.RequestID == "" {
					t.Fatal("RequestID was not generated")
				}
				if got.Timestamp.IsZero() {
					t.Fatal("Timestamp was not set")
				}
				var envelope map[string]any
				if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &envelope); err != nil {
					t.Fatalf("json: %v", err)
				}
				ts := envelope["timestamp"].(string)
				if _, err := time.Parse(time.RFC3339Nano, ts); err != nil {
					t.Fatalf("generated timestamp %q is not RFC3339Nano: %v", ts, err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.log")
			logger, err := NewLogger(path)
			if err != nil {
				t.Fatalf("NewLogger: %v", err)
			}
			if err := logger.Log(tt.event); err != nil {
				t.Fatalf("Log: %v", err)
			}
			if err := logger.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("ReadFile: %v", err)
			}
			var got AuditEvent
			if err := json.Unmarshal(bytesTrimOneLine(raw), &got); err != nil {
				t.Fatalf("Unmarshal event: %v\nraw=%s", err, raw)
			}
			tt.check(t, string(raw), got)
		})
	}
}

func TestLogConcurrentWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logger, err := NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	const goroutines = 10
	const perGoroutine = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for n := 0; n < perGoroutine; n++ {
				event := AuditEvent{
					Method:             "tools/call",
					ToolName:           "safe_search",
					Action:             "monitor",
					Reason:             "concurrent write",
					PolicyMode:         "monitor",
					ClientAddress:      "127.0.0.1:1",
					PayloadSHA256:      "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
					RedactedFieldCount: id,
				}
				if err := logger.Log(event); err != nil {
					t.Errorf("Log: %v", err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
	if err := logger.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer file.Close()

	ids := make(map[string]struct{}, goroutines*perGoroutine)
	scanner := bufio.NewScanner(file)
	lines := 0
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			t.Fatal("found empty line; writes interleaved or corrupted")
		}
		var event AuditEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("line %d is not valid JSON %q: %v", lines+1, line, err)
		}
		if event.RequestID == "" {
			t.Fatalf("line %d missing request_id", lines+1)
		}
		if _, dup := ids[event.RequestID]; dup {
			t.Fatalf("duplicate request_id %q", event.RequestID)
		}
		ids[event.RequestID] = struct{}{}
		if event.Timestamp.IsZero() {
			t.Fatalf("line %d missing timestamp", lines+1)
		}
		if event.PayloadSHA256 == "" {
			t.Fatalf("line %d missing payload_sha256", lines+1)
		}
		if strings.Contains(line, `"body"`) || strings.Contains(line, `"payload"`) {
			t.Fatalf("line leaked a payload field: %s", line)
		}
		lines++
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if lines != goroutines*perGoroutine {
		t.Fatalf("line count = %d, want %d", lines, goroutines*perGoroutine)
	}
}

func TestNewLoggerDefaultPath(t *testing.T) {
	if DefaultLogPath != "audit.log" {
		t.Fatalf("DefaultLogPath = %q, want audit.log", DefaultLogPath)
	}
}

func bytesTrimOneLine(raw []byte) []byte {
	return []byte(strings.TrimSpace(string(raw)))
}
