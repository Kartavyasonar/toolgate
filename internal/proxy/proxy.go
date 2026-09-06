package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/kartavyasonar/toolgate/internal/audit"
	"github.com/kartavyasonar/toolgate/internal/policy"
)

// Config holds the configuration for the ToolGate proxy server.
type Config struct {
	ListenAddr  string
	TargetURL   string
	Policy      policy.Policy
	AuditLogger *audit.Logger
}

// Server is the ToolGate runtime proxy.
type Server struct {
	cfg    Config
	client *http.Client
}

// New creates a new proxy Server.
func New(cfg Config) *Server {
	return &Server{
		cfg: cfg,
		client: &http.Client{
			Timeout: 20 * time.Second,
		},
	}
}

// jsonRPCRequest represents a generic JSON-RPC 2.0 request.
type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// jsonRPCResponse represents a generic JSON-RPC 2.0 response.
type jsonRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      any         `json:"id"`
	Result  any         `json:"result,omitempty"`
	Error   *rpcError   `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// toolsCallParams represents the params for a "tools/call" request.
type toolsCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// Start begins listening for HTTP traffic.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleProxy)

	srv := &http.Server{
		Addr:    s.cfg.ListenAddr,
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	slog.Info("ToolGate proxy listening", "addr", s.cfg.ListenAddr, "target", s.cfg.TargetURL, "mode", s.cfg.Policy.Mode)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read the raw body so we can hash it and parse it
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req jsonRPCRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		s.writeRPCError(w, req.ID, -32700, "Parse error")
		return
	}

	// If it's not a tools/call, just forward it blindly (e.g., initialize, tools/list)
	if req.Method != "tools/call" {
		s.forwardRequest(w, r, bodyBytes, req.ID)
		return
	}

	// Parse the tools/call params
	var params toolsCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		s.writeRPCError(w, req.ID, -32602, "Invalid params")
		return
	}

	// EVALUATE POLICY
	decision := policy.Evaluate(params.Name, params.Arguments, s.cfg.Policy)

	// AUDIT LOG
	payloadHash := audit.HashPayload(bodyBytes)
	auditEvent := audit.AuditEvent{
		Method:        req.Method,
		ToolName:      params.Name,
		Action:        decision.Action,
		Reason:        decision.Reason,
		PolicyMode:    s.cfg.Policy.Mode,
		ClientAddress: r.RemoteAddr,
		PayloadSHA256: payloadHash,
	}
	
	if s.cfg.AuditLogger != nil {
		if err := s.cfg.AuditLogger.Log(auditEvent); err != nil {
			slog.Error("Failed to write audit log", "error", err)
		}
	}

	// ENFORCE DECISION
	if decision.Action == "deny" {
		slog.Warn("Tool call DENIED", "tool", params.Name, "reason", decision.Reason)
		s.writeRPCError(w, req.ID, -32600, fmt.Sprintf("ToolGate Policy Denied: %s", decision.Reason))
		return
	}

	if decision.Action == "monitor" {
		slog.Info("Tool call MONITORED (violation detected but mode is monitor)", "tool", params.Name, "reason", decision.Reason)
	}

	// ALLOW (or monitor forward)
	s.forwardRequest(w, r, bodyBytes, req.ID)
}

func (s *Server) forwardRequest(w http.ResponseWriter, originalReq *http.Request, body []byte, reqID any) {
	proxyReq, err := http.NewRequestWithContext(originalReq.Context(), http.MethodPost, s.cfg.TargetURL, bytes.NewReader(body))
	if err != nil {
		s.writeRPCError(w, reqID, -32603, "Internal proxy error")
		return
	}
	proxyReq.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(proxyReq)
	if err != nil {
		s.writeRPCError(w, reqID, -32603, fmt.Sprintf("Upstream error: %v", err))
		return
	}
	defer resp.Body.Close()

	// Copy headers
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (s *Server) writeRPCError(w http.ResponseWriter, id any, code int, message string) {
	resp := jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &rpcError{
			Code:    code,
			Message: message,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // JSON-RPC usually returns 200 OK even for RPC errors
	json.NewEncoder(w).Encode(resp)
}