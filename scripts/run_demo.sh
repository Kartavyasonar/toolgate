#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 examples/unsafe_mcp_server.py &
SERVER_PID=$!

cleanup() {
  kill "${SERVER_PID}" 2>/dev/null || true
  wait "${SERVER_PID}" 2>/dev/null || true
}
trap cleanup EXIT

ready=0
for _ in $(seq 1 50); do
  if curl -sf -X POST "http://127.0.0.1:8000/mcp" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' >/dev/null; then
    ready=1
    break
  fi
  sleep 0.2
done

if [[ "${ready}" -ne 1 ]]; then
  echo "unsafe MCP mock did not become ready on http://127.0.0.1:8000/mcp" >&2
  exit 1
fi

echo "=== toolgate scan ==="
go run ./cmd/toolgate scan --target "http://127.0.0.1:8000/mcp"
echo "=== scan complete ==="
