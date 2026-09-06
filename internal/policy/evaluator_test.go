package policy

import (
	"strings"
	"testing"
)

func testPolicy(mode, defaultAction string, tools []ToolRule, rules ArgumentRules) Policy {
	return Policy{
		Version:       1,
		Mode:          mode,
		DefaultAction: defaultAction,
		Tools:         tools,
		ArgumentRules: rules,
	}
}

func TestEvaluate(t *testing.T) {
	listed := []ToolRule{
		{Name: "safe_search", Action: ActionAllow, Reason: "Search is permitted"},
		{Name: "run_command", Action: ActionDeny, Reason: "Shell execution is not allowed"},
	}
	allRules := ArgumentRules{
		BlockPathTraversal:       true,
		BlockShellMetacharacters: true,
		BlockCloudMetadata:       true,
	}

	tests := []struct {
		name      string
		policy    Policy
		tool      string
		args      map[string]any
		wantAct   string
		wantSub   string
		wantExact string
	}{
		{
			name:    "explicit allow tool",
			policy:  testPolicy(ModeMonitor, ActionDeny, listed, allRules),
			tool:    "safe_search",
			args:    map[string]any{"query": "release notes"},
			wantAct: ActionAllow,
			wantSub: "Search is permitted",
		},
		{
			name:    "explicit deny tool",
			policy:  testPolicy(ModeEnforce, ActionAllow, listed, allRules),
			tool:    "run_command",
			args:    map[string]any{"command": "status"},
			wantAct: ActionDeny,
			wantSub: "Shell execution is not allowed",
		},
		{
			name:      "default action allow fallback",
			policy:    testPolicy(ModeEnforce, ActionAllow, listed, allRules),
			tool:      "summarize_public_text",
			args:      map[string]any{"text": "hello"},
			wantAct:   ActionAllow,
			wantExact: "default action is allow",
		},
		{
			name:      "default action deny fallback",
			policy:    testPolicy(ModeEnforce, ActionDeny, listed, allRules),
			tool:      "unknown_tool",
			args:      map[string]any{"x": "y"},
			wantAct:   ActionDeny,
			wantExact: "default action is deny",
		},
		{
			name:    "path traversal in enforce denies",
			policy:  testPolicy(ModeEnforce, ActionAllow, listed, allRules),
			tool:    "safe_search",
			args:    map[string]any{"path": "../etc/shadow"},
			wantAct: ActionDeny,
			wantSub: "Argument violated rule: block_path_traversal",
		},
		{
			name:    "path traversal in monitor reports monitor",
			policy:  testPolicy(ModeMonitor, ActionAllow, listed, allRules),
			tool:    "safe_search",
			args:    map[string]any{"path": "../secret"},
			wantAct: ActionMonitor,
			wantSub: "Argument violated rule: block_path_traversal",
		},
		{
			name:    "encoded path traversal ..%2F",
			policy:  testPolicy(ModeEnforce, ActionAllow, listed, allRules),
			tool:    "safe_search",
			args:    map[string]any{"path": "..%2Fetc%2Fpasswd"},
			wantAct: ActionDeny,
			wantSub: RulePathTraversal,
		},
		{
			name:    "encoded path traversal ..%2f",
			policy:  testPolicy(ModeEnforce, ActionAllow, listed, allRules),
			tool:    "safe_search",
			args:    map[string]any{"path": "..%2fpasswd"},
			wantAct: ActionDeny,
			wantSub: RulePathTraversal,
		},
		{
			name:    "encoded path traversal %2e%2e%2f",
			policy:  testPolicy(ModeEnforce, ActionAllow, listed, allRules),
			tool:    "safe_search",
			args:    map[string]any{"path": "%2e%2e%2fetc/passwd"},
			wantAct: ActionDeny,
			wantSub: RulePathTraversal,
		},
		{
			name:    "absolute path /etc/passwd",
			policy:  testPolicy(ModeEnforce, ActionAllow, listed, allRules),
			tool:    "safe_search",
			args:    map[string]any{"path": "/etc/passwd"},
			wantAct: ActionDeny,
			wantSub: RulePathTraversal,
		},
		{
			name:    "shell metacharacters in enforce denies",
			policy:  testPolicy(ModeEnforce, ActionAllow, listed, allRules),
			tool:    "safe_search",
			args:    map[string]any{"query": "docs; rm -rf /"},
			wantAct: ActionDeny,
			wantSub: "Argument violated rule: block_shell_metacharacters",
		},
		{
			name:    "shell metacharacters in monitor reports monitor",
			policy:  testPolicy(ModeMonitor, ActionAllow, listed, allRules),
			tool:    "safe_search",
			args:    map[string]any{"query": "docs && wget http://example.invalid"},
			wantAct: ActionMonitor,
			wantSub: RuleShellMetacharacters,
		},
		{
			name:    "shell pipe and substitution",
			policy:  testPolicy(ModeEnforce, ActionAllow, listed, allRules),
			tool:    "safe_search",
			args:    map[string]any{"query": "echo `id` | bash"},
			wantAct: ActionDeny,
			wantSub: RuleShellMetacharacters,
		},
		{
			name:    "cloud metadata ipv4",
			policy:  testPolicy(ModeEnforce, ActionAllow, listed, allRules),
			tool:    "safe_search",
			args:    map[string]any{"url": "http://169.254.169.254/latest/meta-data/"},
			wantAct: ActionDeny,
			wantSub: "Argument violated rule: block_cloud_metadata",
		},
		{
			name:    "cloud metadata google hostname in monitor",
			policy:  testPolicy(ModeMonitor, ActionAllow, listed, allRules),
			tool:    "safe_search",
			args:    map[string]any{"url": "http://metadata.google.internal/computeMetadata/v1/"},
			wantAct: ActionMonitor,
			wantSub: RuleCloudMetadata,
		},
		{
			name:    "nil arguments skip argument rules",
			policy:  testPolicy(ModeEnforce, ActionAllow, listed, allRules),
			tool:    "safe_search",
			args:    nil,
			wantAct: ActionAllow,
			wantSub: "Search is permitted",
		},
		{
			name:   "deeply nested path traversal",
			policy: testPolicy(ModeEnforce, ActionAllow, listed, allRules),
			tool:   "safe_search",
			args: map[string]any{
				"outer": map[string]any{
					"inner": []any{
						map[string]any{"path": "notes/../../etc/passwd"},
					},
				},
			},
			wantAct: ActionDeny,
			wantSub: RulePathTraversal,
		},
		{
			name:   "deeply nested cloud metadata",
			policy: testPolicy(ModeMonitor, ActionAllow, listed, allRules),
			tool:   "safe_search",
			args: map[string]any{
				"filters": []any{
					[]any{"ok", map[string]any{"host": "169.254.169.254"}},
				},
			},
			wantAct: ActionMonitor,
			wantSub: RuleCloudMetadata,
		},
		{
			name: "argument rules disabled do not override allow",
			policy: testPolicy(ModeEnforce, ActionAllow, listed, ArgumentRules{
				BlockPathTraversal:       false,
				BlockShellMetacharacters: false,
				BlockCloudMetadata:       false,
			}),
			tool:    "safe_search",
			args:    map[string]any{"path": "../etc/passwd", "cmd": "rm && curl 169.254.169.254"},
			wantAct: ActionAllow,
			wantSub: "Search is permitted",
		},
		{
			name:    "benign query does not trip shell command tokens",
			policy:  testPolicy(ModeEnforce, ActionAllow, listed, allRules),
			tool:    "safe_search",
			args:    map[string]any{"query": "share bashful documents"},
			wantAct: ActionAllow,
			wantSub: "Search is permitted",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Evaluate(tt.tool, tt.args, tt.policy)
			if got.Action != tt.wantAct {
				t.Errorf("Action = %q, want %q (reason=%q)", got.Action, tt.wantAct, got.Reason)
			}
			if tt.wantExact != "" && got.Reason != tt.wantExact {
				t.Errorf("Reason = %q, want exact %q", got.Reason, tt.wantExact)
			}
			if tt.wantSub != "" && !strings.Contains(got.Reason, tt.wantSub) {
				t.Errorf("Reason = %q, want substring %q", got.Reason, tt.wantSub)
			}
		})
	}
}

func TestParseDefaultPolicyFile(t *testing.T) {
	policy, err := Load("../../policies/default.yaml")
	if err != nil {
		t.Fatalf("Load default.yaml: %v", err)
	}
	if policy.Mode != ModeMonitor {
		t.Fatalf("Mode = %q, want %q", policy.Mode, ModeMonitor)
	}
	if policy.DefaultAction != ActionAllow {
		t.Fatalf("DefaultAction = %q, want %q", policy.DefaultAction, ActionAllow)
	}

	got := Evaluate("run_command", map[string]any{"command": "status"}, policy)
	if got.Action != ActionDeny {
		t.Fatalf("run_command Action = %q, want deny", got.Action)
	}

	got = Evaluate("safe_search", map[string]any{"query": "../secrets"}, policy)
	if got.Action != ActionMonitor {
		t.Fatalf("monitor path traversal Action = %q, want monitor", got.Action)
	}
}

func TestParseRejectsUnknownAndDuplicates(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name:    "unknown mode",
			yaml:    "version: 1\nmode: lock\ndefault_action: allow\ntools: []\n",
			wantErr: `unknown mode "lock"`,
		},
		{
			name:    "unknown default_action",
			yaml:    "version: 1\nmode: enforce\ndefault_action: drop\ntools: []\n",
			wantErr: `unknown default_action "drop"`,
		},
		{
			name: "duplicate tool names in list",
			yaml: `version: 1
mode: monitor
default_action: allow
tools:
  - name: safe_search
    action: allow
  - name: safe_search
    action: deny
    reason: dup
`,
			wantErr: `duplicate tool name "safe_search"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml))
			if err == nil {
				t.Fatal("Parse() error = nil, want error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Parse() error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}
