package policy

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

func Load(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("read policy %s: %w", path, err)
	}
	policy, err := Parse(data)
	if err != nil {
		return Policy{}, fmt.Errorf("parse policy %s: %w", path, err)
	}
	return policy, nil
}

func Parse(data []byte) (Policy, error) {
	var policy Policy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return Policy{}, fmt.Errorf("unmarshal policy yaml: %w", err)
	}
	if err := validate(policy); err != nil {
		return Policy{}, err
	}
	return policy, nil
}

func validate(policy Policy) error {
	switch policy.Mode {
	case ModeMonitor, ModeEnforce:
	default:
		return fmt.Errorf("unknown mode %q", policy.Mode)
	}

	switch policy.DefaultAction {
	case ActionAllow, ActionDeny:
	default:
		return fmt.Errorf("unknown default_action %q", policy.DefaultAction)
	}

	seen := make(map[string]struct{}, len(policy.Tools))
	for _, tool := range policy.Tools {
		name := strings.TrimSpace(tool.Name)
		if name == "" {
			return fmt.Errorf("tool entry is missing name")
		}
		if _, exists := seen[name]; exists {
			return fmt.Errorf("duplicate tool name %q", name)
		}
		seen[name] = struct{}{}
		switch tool.Action {
		case ActionAllow, ActionDeny:
		default:
			return fmt.Errorf("tool %q has unknown action %q", name, tool.Action)
		}
	}
	return nil
}

type ToolRules []ToolRule

func (t *ToolRules) UnmarshalYAML(value *yaml.Node) error {
	if value == nil || value.Tag == "!!null" || value.Kind == 0 {
		*t = nil
		return nil
	}

	switch value.Kind {
	case yaml.SequenceNode:
		var list []ToolRule
		if err := value.Decode(&list); err != nil {
			return fmt.Errorf("decode tools list: %w", err)
		}
		*t = list
		return nil
	case yaml.MappingNode:
		if len(value.Content)%2 != 0 {
			return fmt.Errorf("malformed tools mapping")
		}
		rules := make([]ToolRule, 0, len(value.Content)/2)
		for i := 0; i < len(value.Content); i += 2 {
			nameNode := value.Content[i]
			bodyNode := value.Content[i+1]
			var rule ToolRule
			if err := bodyNode.Decode(&rule); err != nil {
				return fmt.Errorf("decode tool %q: %w", nameNode.Value, err)
			}
			rule.Name = nameNode.Value
			rules = append(rules, rule)
		}
		*t = rules
		return nil
	default:
		return fmt.Errorf("tools must be a list or a name-keyed mapping")
	}
}
