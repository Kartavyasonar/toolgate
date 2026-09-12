import http from 'k6/http';
import { check, sleep } from 'k6';

// Run with 20 virtual users for 30 seconds
export const options = {
    vus: 20,
    duration: '30s',
};

const PROXY_URL = 'http://127.0.0.1:9090/';

const safePayload = JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: {
        name: "safe_search",
        arguments: { query: "hello world" }
    }
});

const attackPayload = JSON.stringify({
    jsonrpc: "2.0",
    id: 2,
    method: "tools/call",
    params: {
        name: "run_command",
        arguments: { cmd: "rm -rf /" }
    }
});

export default function () {
    const params = { headers: { 'Content-Type': 'application/json' } };

    // 1. Send a safe request (Proxy allows it, forwards to Python)
    const safeRes = http.post(PROXY_URL, safePayload, params);
    check(safeRes, {
        'safe request status is 200': (r) => r.status === 200,
        'safe request forwarded successfully': (r) => r.json('result') !== undefined,
    });

    // 2. Send an attack request (Proxy blocks it, returns error -32600)
    const attackRes = http.post(PROXY_URL, attackPayload, params);
    check(attackRes, {
        'attack request status is 200': (r) => r.status === 200, // JSON-RPC returns 200 OK for RPC errors
        'attack blocked by policy': (r) => r.json('error.code') === -32600,
    });

    sleep(0.1); // Small pause to simulate real pacing
}