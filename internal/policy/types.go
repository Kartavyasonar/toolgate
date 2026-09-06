package policy

const (
	ModeMonitor = "monitor"
	ModeEnforce = "enforce"

	ActionAllow   = "allow"
	ActionDeny    = "deny"
	ActionMonitor = "monitor"

	RulePathTraversal       = "block_path_traversal"
	RuleShellMetacharacters = "block_shell_metacharacters"
	RuleCloudMetadata       = "block_cloud_metadata"
)

type Policy struct {
	Version       int           `yaml:"version"`
	Mode          string        `yaml:"mode"`
	DefaultAction string        `yaml:"default_action"`
	Tools         ToolRules     `yaml:"tools"`
	ArgumentRules ArgumentRules `yaml:"argument_rules"`
	Redaction     Redaction     `yaml:"redaction"`
	Audit         Audit         `yaml:"audit"`
}

type ToolRule struct {
	Name   string `yaml:"name"`
	Action string `yaml:"action"`
	Reason string `yaml:"reason"`
}

type ArgumentRules struct {
	BlockPathTraversal       bool `yaml:"block_path_traversal"`
	BlockShellMetacharacters bool `yaml:"block_shell_metacharacters"`
	BlockCloudMetadata       bool `yaml:"block_cloud_metadata"`
}

type Redaction struct {
	RequestFields  []string `yaml:"request_fields"`
	ResponseFields []string `yaml:"response_fields"`
}

type Audit struct {
	LogAllCalls        bool `yaml:"log_all_calls"`
	LogBlockedCalls    bool `yaml:"log_blocked_calls"`
	IncludePayloadHash bool `yaml:"include_payload_hash"`
}

type Decision struct {
	Action string
	Reason string
}
