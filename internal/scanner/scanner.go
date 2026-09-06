package scanner

import (
	"fmt"
	"strings"

	"github.com/kartavyasonar/toolgate/internal/mcp"
)

type Finding struct {
	Tool     string
	Rule     string
	Severity string
	Message  string
}

var suspiciousDescriptionPhrases = []string{
	"ignore previous",
	"environment variable",
	"shell",
	"exec",
	"curl",
	"wget",
	"base64",
	"secret",
	"token",
	"password",
	"private key",
	"http://",
	"https://",
}

var dangerousNameFragments = []string{
	"shell",
	"exec",
	"command",
	"run_command",
	"file",
	"read_file",
	"write_file",
	"delete",
	"fetch_url",
	"http",
}

func Scan(tools []mcp.Tool) []Finding {
	var findings []Finding
	for _, tool := range tools {
		findings = append(findings, scanTool(tool)...)
	}
	return findings
}

func scanTool(tool mcp.Tool) []Finding {
	var findings []Finding

	if len(tool.InputSchema) == 0 {
		findings = append(findings, Finding{
			Tool:     tool.Name,
			Rule:     "missing_schema",
			Severity: "high",
			Message:  "tool has an empty or missing input schema",
		})
	}

	if additionalPropertiesTrue(tool.InputSchema) {
		findings = append(findings, Finding{
			Tool:     tool.Name,
			Rule:     "permissive_schema",
			Severity: "medium",
			Message:  "input schema sets additionalProperties to true",
		})
	}

	desc := strings.ToLower(tool.Description)
	for _, phrase := range suspiciousDescriptionPhrases {
		if strings.Contains(desc, phrase) {
			findings = append(findings, Finding{
				Tool:     tool.Name,
				Rule:     "suspicious_description",
				Severity: "medium",
				Message:  fmt.Sprintf("description contains %q", phrase),
			})
			break
		}
	}

	name := strings.ToLower(tool.Name)
	for _, fragment := range dangerousNameFragments {
		if strings.Contains(name, fragment) {
			findings = append(findings, Finding{
				Tool:     tool.Name,
				Rule:     "dangerous_tool_name",
				Severity: "high",
				Message:  fmt.Sprintf("tool name contains %q", fragment),
			})
			break
		}
	}

	return findings
}

func additionalPropertiesTrue(schema map[string]any) bool {
	if schema == nil {
		return false
	}
	v, ok := schema["additionalProperties"]
	if !ok {
		return false
	}
	b, ok := v.(bool)
	return ok && b
}
