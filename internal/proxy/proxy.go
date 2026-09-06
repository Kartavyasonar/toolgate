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

	"github.com/kartavyasonar/invokecordon/internal/audit"
	"github.com/kartavyasonar/invokecordon/internal/metrics"
	"github.com/kartavyasonar/invokecordon/internal/policy"
	"github.com/kartavyasonar/invokecordon/internal/redact"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Config struct {
	ListenAddr  string
	TargetURL   string
	Policy      policy.Policy
	AuditLogger *audit.Logger
}

type Server struct {
	cfg    Config
	client *http.Client
}

func New(cfg Config) *Server {
	return &Server{
		cfg: cfg,
		client: &http.Client{
			Timeout: 20 * time.Second,
		},
	}
}

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      any       `json:"id"`
	Result  any       `json:"result,omitempty"`
	Error   *rpcError `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type toolsCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleProxy)
	mux.Handle("/metrics", promhttp.Handler()) // <--- METRICS ENDPOINT

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

	slog.Info("InvokeCordon proxy listening", "addr", s.cfg.ListenAddr, "metrics", "/metrics")
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

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

	if req.Method != "tools/call" {
		metrics.RequestsTotal.WithLabelValues(req.Method, "forwarded").Inc()
		s.forwardRequest(w, r, bodyBytes, req.ID)
		return
	}

	var params toolsCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		s.writeRPCError(w, req.ID, -32602, "Invalid params")
		return
	}

	// 1. EVALUATE POLICY
	decision := policy.Evaluate(params.Name, params.Arguments, s.cfg.Policy)

	// 2. REDACT (if allowed/monitored)
	redactCount := 0
	if decision.Action != "deny" {
		// Only redact if we are actually forwarding the request
		if s.cfg.Policy.Redaction.RequestFields != nil {
			redactedArgs, count := redact.Redact(params.Arguments, s.cfg.Policy.Redaction.RequestFields)
			if count > 0 {
				params.Arguments = redactedArgs.(map[string]any)
				redactCount = count
				metrics.RedactionsTotal.Add(float64(count))
				
				// Re-marshal the request with redacted arguments
				newParamsBytes, _ := json.Marshal(params)
				req.Params = newParamsBytes
				bodyBytes, _ = json.Marshal(req)
			}
		}
	}

	// 3. AUDIT
	payloadHash := audit.HashPayload(bodyBytes)
	auditEvent := audit.AuditEvent{
		Method:             req.Method,
		ToolName:           params.Name,
		Action:             decision.Action,
		Reason:             decision.Reason,
		PolicyMode:         s.cfg.Policy.Mode,
		ClientAddress:      r.RemoteAddr,
		PayloadSHA256:      payloadHash,
		RedactedFieldCount: redactCount,
	}
	if s.cfg.AuditLogger != nil {
		s.cfg.AuditLogger.Log(auditEvent)
	}

	// 4. ENFORCE & METRICS
	metrics.RequestsTotal.WithLabelValues(req.Method, decision.Action).Inc()
	metrics.Latency.WithLabelValues(req.Method).Observe(time.Since(start).Seconds())

	if decision.Action == "deny" {
		s.writeRPCError(w, req.ID, -32600, fmt.Sprintf("InvokeCordon Policy Denied: %s", decision.Reason))
		return
	}

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
		Error:   &rpcError{Code: code, Message: message},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}