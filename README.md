# InvokeCordon

InvokeCordon is a security scanner and runtime policy gateway for MCP (Model Context Protocol) servers.

It statically analyzes MCP servers to find unsafe tools. At runtime, it acts as a proxy between AI clients and MCP servers to enforce YAML security policies. It blocks or monitors tool calls, redacts secrets, and writes every decision to an audit log.

Note: InvokeCordon is an independent open source project. It is not affiliated with the official Model Context Protocol project.

Warning: Only scan or proxy systems you own or have permission to test.

Status: v0.1 (early development). HTTP JSON-RPC transport only.

## The Problem

MCP lets AI agents call real tools like shells, databases, and HTTP endpoints. This creates security risks that most deployments ignore:

* Over-privileged tools (a tool that can run arbitrary shell commands).
* Tool poisoning (malicious instructions hidden in tool descriptions).
* Unvalidated arguments (path traversal or shell injection payloads passing straight to the tool).
* No audit trail (no way to prove which agent called which tool).

InvokeCordon has two modes to fix this:

1. Scan: Static analysis of the server tools. It outputs findings, a 0 to 100 security score, and a letter grade.
2. Proxy: A runtime gateway that enforces policies on every `tools/call` request.

## Features

* MCP client using JSON-RPC 2.0 over HTTP.
* Static scanner with four detection rules and weighted scoring.
* Reports in text, JSON, and markdown.
* YAML policy engine with `monitor` and `enforce` modes.
* Recursive argument inspection for path traversal, shell metacharacters, and cloud metadata endpoints (like 169.254.169.254).
* Runtime HTTP proxy with per-tool allow and deny rules.
* Recursive redaction of secrets (passwords, tokens) from arguments before forwarding.
* Concurrent-safe JSONL audit log. It stores SHA-256 payload hashes instead of raw data.
* Prometheus metrics at `/metrics`.
* Table-driven tests across all packages.

## Quickstart

Prerequisites: Go 1.23+, Python 3.10+.

### 1. Start a mock MCP server

```bash
pip install -r examples/requirements.txt
python examples/unsafe_mcp_server.py   # port 8000, intentionally unsafe
python examples/safe_mcp_server.py     # port 8001, strict schemas
```

These are mock servers. They do not execute real commands or read real files.

### 2. Scan it

```bash
go run ./cmd/invokecordon scan --target http://127.0.0.1:8000/mcp --format=markdown
```

Example output against the unsafe server:

```markdown
# InvokeCordon Scan Report

**Target:** `http://127.0.0.1:8000/mcp`

**Score:** 0/100 (**F**)

## Findings (8)

| Tool | Rule | Message |
| --- | --- | --- |
| run_command | dangerous_tool_name | tool name contains "command" |
| run_command | permissive_schema | input schema sets additionalProperties to true |
| run_command | suspicious_description | description contains "ignore previous" |

## Deductions

| Rule | Points |
| --- | --- |
| dangerous_tool_name | -60 |
| permissive_schema | -30 |
| suspicious_description | -20 |
```

### 3. Run the proxy

```bash
go run ./cmd/invokecordon proxy \
  --listen 127.0.0.1:9090 \
  --target http://127.0.0.1:8000/mcp \
  --policy policies/default.yaml
```

### 4. Send traffic through the gateway

Create `attack.json`:

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run_command","arguments":{"cmd":"rm -rf /"}}}
```

Create `safe.json`:

```json
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"safe_search","arguments":{"query":"hello"}}}
```

Send the requests:

```bash
curl -X POST http://127.0.0.1:9090/ -H "Content-Type: application/json" -d @attack.json
curl -X POST http://127.0.0.1:9090/ -H "Content-Type: application/json" -d @safe.json
```

If `mode: enforce` is set in your policy, the proxy blocks the attack and returns an error:

```json
{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"InvokeCordon Policy Denied: Argument violated rule: block_shell_metacharacters"}}
```

### 5. Check the audit log

```bash
tail -n 1 audit.log
```

```json
{"timestamp":"2026-09-06T11:59:15.985141Z","request_id":"46059d75-5bfe-4bb3-aeef-f2dada29bb07","method":"tools/call","tool_name":"run_command","action":"monitor","reason":"Argument violated rule: block_shell_metacharacters","policy_mode":"monitor","client_address":"127.0.0.1:58949","payload_sha256":"221c427a29559182f34f27225e51c97c8eb2f4ad0e7465b9d120d0bfee24d3f6","redacted_field_count":0}
```

## CLI Reference

### invokecordon scan

* `--target` (required): MCP server URL.
* `--format` (default text): Output format (text, json, markdown).
* `--output` (default stdout): File path for the report.

Scoring starts at 100. Deductions: `missing_schema` (-15), `permissive_schema` (-10), `suspicious_description` (-10), `dangerous_tool_name` (-20). Minimum score is 0. Grades: A (90+), B (80+), C (70+), D (60+), F (below 60).

### invokecordon proxy

* `--listen` (default 127.0.0.1:9090): Proxy listen address.
* `--target` (default http://127.0.0.1:8000/mcp): Upstream MCP server.
* `--policy` (default policies/default.yaml): Path to policy file.

## Policy Reference

```yaml
version: 1
mode: monitor            # monitor = log violations, forward traffic
                         # enforce = deny violations at the edge
default_action: allow    # fallback for tools not listed below

tools:
  - name: safe_search
    action: allow
  - name: run_command
    action: deny
    reason: Shell execution is not allowed
  - name: read_file
    action: deny
    reason: Direct filesystem access is not allowed
  - name: fetch_url
    action: deny
    reason: Arbitrary outbound URL fetching is not allowed

argument_rules:          # applied recursively to all string arguments
  block_path_traversal: true        # ../, ..%2F, %2e%2e%2f, /etc/passwd
  block_shell_metacharacters: true  # ; && || | ` $() rm curl wget bash sh
  block_cloud_metadata: true        # 169.254.169.254, metadata.google.internal

redaction:
  request_fields: [password, token, api_key, secret, private_key]
  response_fields: [ssn, credit_card, password, token, api_key]

audit:
  log_all_calls: true
  log_blocked_calls: true
  include_payload_hash: true
```

How decisions work:
The proxy checks tool-level rules first. If the tool is not listed, it uses the `default_action`. Next, it checks the argument rules recursively. If an argument rule is violated, the proxy denies the request in `enforce` mode, or logs it and forwards it in `monitor` mode.

## Metrics

Exposed at `/metrics` on the proxy listener in Prometheus format:

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `invokecordon_requests_total` | counter | method, decision | Requests processed |
| `invokecordon_request_duration_seconds` | histogram | method | End-to-end proxy latency |
| `invokecordon_redactions_total` | counter | none | Sensitive fields redacted |

## Project Layout

```text
cmd/invokecordon/          CLI entrypoint (scan, proxy)
internal/mcp/          JSON-RPC 2.0 client and MCP types
internal/scanner/      Detection rules, scoring engine
internal/report/       Text, JSON, and Markdown report rendering
internal/policy/       YAML policy loader, validator, evaluator
internal/proxy/        Runtime HTTP proxy with enforcement
internal/audit/        Concurrent-safe JSONL audit logger
internal/redact/       Recursive secret and PII redaction
internal/metrics/      Prometheus metric definitions
examples/              Mock unsafe (8000) and safe (8001) MCP servers
policies/              Example policy files
docs/                  Threat model and design notes
scripts/               Demo and utility scripts
```

## Threat Model

See `docs/threat-model.md` for the full threat model.

## Limitations

* Only supports HTTP JSON-RPC transport right now.
* Detection is based on patterns and argument inspection. It will not catch every encoding bypass.
* InvokeCordon reduces tool-level risk. It does not fix model-level prompt injection.
* Example servers are mocks for local testing.

## Roadmap (v0.2)

* OpenTelemetry tracing.
* Grafana dashboard JSON and k6 load tests.
* Response-side redaction.
* stdio MCP transport.

## Development

```bash
go build ./...
go vet ./...
go test ./...
```

## Contributing

Issues and pull requests are welcome. Keep changes small, tested, and scoped. Run the full test suite before submitting.

## License

Apache License 2.0.