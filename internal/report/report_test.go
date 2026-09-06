package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kartavyasonar/invokecordon/internal/scanner"
)

func sampleResult() scanner.ScoreResult {
	findings := []scanner.Finding{
		{Tool: "delete_all", Rule: "dangerous_tool_name", Message: "tool name suggests an irreversible action"},
		{Tool: "delete_all", Rule: "missing_schema", Message: "tool defines no input schema"},
		{Tool: "fetch_url", Rule: "permissive_schema", Message: "schema places no constraints on arguments"},
	}
	return scanner.Score(findings)
}

func cleanResult() scanner.ScoreResult {
	return scanner.Score(nil)
}

func TestParseFormat(t *testing.T) {
	tests := []struct {
		input   string
		want    Format
		wantErr bool
	}{
		{"text", FormatText, false},
		{"JSON", FormatJSON, false},
		{"markdown", FormatMarkdown, false},
		{"yaml", "", true},
	}
	for _, tt := range tests {
		got, err := ParseFormat(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseFormat(%q) expected error", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseFormat(%q) unexpected error: %v", tt.input, err)
		}
		if got != tt.want {
			t.Errorf("ParseFormat(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestRenderText(t *testing.T) {
	r := New("http://localhost:8000/mcp", sampleResult())
	got, _ := r.Render(FormatText)
	if !strings.Contains(got, "Score:  55/100 (F)") {
		t.Errorf("missing score line in:\n%s", got)
	}
	if !strings.Contains(got, "[dangerous_tool_name] delete_all") {
		t.Errorf("missing finding in:\n%s", got)
	}
}

func TestRenderJSON(t *testing.T) {
	r := New("http://localhost:8000/mcp", sampleResult())
	got, _ := r.Render(FormatJSON)
	var parsed map[string]any
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if parsed["score"].(float64) != 55 {
		t.Errorf("wrong score")
	}
}

func TestRenderMarkdown(t *testing.T) {
	r := New("http://localhost:8000/mcp", cleanResult())
	got, _ := r.Render(FormatMarkdown)
	if !strings.Contains(got, "100/100 (**A**)") {
		t.Errorf("missing perfect score in:\n%s", got)
	}
}