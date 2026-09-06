package proxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kartavyasonar/invokecordon/internal/audit"
	"github.com/kartavyasonar/invokecordon/internal/policy"
)

func setupTestProxy(t *testing.T, p policy.Policy) (*Server, *httptest.Server, *audit.Logger) {
	// Mock upstream MCP server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req jsonRPCRequest
		json.NewDecoder(r.Body).Decode(&req)
		
		resp := jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  map[string]any{"content": []map[string]any{{"type": "text", "text": "upstream ok"}}},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))

	logger, err := audit.NewLogger("")
	if err != nil {
		t.Fatalf("audit logger: %v", err)
	}

	srv := New(Config{
		ListenAddr:  "127.0.0.1:0",
		TargetURL:   upstream.URL,
		Policy:      p,
		AuditLogger: logger,
	})

	return srv, upstream, logger
}

func TestProxy_ForwardsNonToolsCall(t *testing.T) {
	p := policy.Policy{Mode: "enforce", DefaultAction: "deny"}
	srv, upstream, _ := setupTestProxy(t, p)
	defer upstream.Close()

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	req := httptest.NewRequest("POST", "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	srv.handleProxy(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}

	var resp jsonRPCResponse
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
}

func TestProxy_DeniesUnsafeToolInEnforceMode(t *testing.T) {
	p := policy.Policy{
		Mode:          "enforce",
		DefaultAction: "allow",
		Tools: []policy.ToolRule{
			{Name: "run_command", Action: "deny", Reason: "no shell"},
		},
	}
	srv, upstream, _ := setupTestProxy(t, p)
	defer upstream.Close()

	body := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"run_command","arguments":{"cmd":"ls"}}}`
	req := httptest.NewRequest("POST", "/", bytes.NewReader([]byte(body)))
	rr := httptest.NewRecorder()

	srv.handleProxy(rr, req)

	var resp jsonRPCResponse
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Error == nil {
		t.Fatal("expected RPC error for denied tool")
	}
	if resp.Error.Code != -32600 {
		t.Errorf("error code = %d", resp.Error.Code)
	}
}

func TestProxy_AllowsSafeTool(t *testing.T) {
	p := policy.Policy{
		Mode:          "enforce",
		DefaultAction: "allow",
	}
	srv, upstream, _ := setupTestProxy(t, p)
	defer upstream.Close()

	body := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"safe_search","arguments":{"q":"hello"}}}`
	req := httptest.NewRequest("POST", "/", bytes.NewReader([]byte(body)))
	rr := httptest.NewRecorder()

	srv.handleProxy(rr, req)

	var resp jsonRPCResponse
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
}
