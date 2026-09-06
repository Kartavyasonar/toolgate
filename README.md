# ToolGate

Security scanner and runtime policy gateway for MCP servers.

ToolGate is an unofficial, independent project. It is not affiliated with, endorsed by, or part of the Model Context Protocol (MCP) project.

## Status

Early development. The scanner can list tools on an MCP HTTP endpoint and flag risky patterns. The runtime proxy is not implemented yet.

## Warning

Scan only systems you own or have explicit permission to test. Unauthorized scanning or probing of third-party services is not permitted.

## Quickstart

Requires Go and Python 3 with FastAPI/Uvicorn.

```bash
pip install -r examples/requirements.txt
python examples/unsafe_mcp_server.py
```

In another terminal:

```bash
go run ./cmd/toolgate scan --target http://127.0.0.1:8000/mcp
```

Or use `scripts/run_demo.sh` (Git Bash or WSL on Windows).
