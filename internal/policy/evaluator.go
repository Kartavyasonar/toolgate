package policy

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var (
	shellCommandPattern = regexp.MustCompile(`(?i)(^|[\s;|&` + "`" + `$'\"(])(rm|curl|wget|bash|sh)([\s;|&` + "`" + `$'\")]|$)`)
	unixAbsPathPattern  = regexp.MustCompile(`(?i)(?:^|[\s"'=])(/(?:etc|usr|var|home|root|proc|sys|dev|tmp|opt|bin|sbin)(?:/|$))`)
)

func Evaluate(toolName string, arguments map[string]any, policy Policy) Decision {
	decision := baseDecision(toolName, policy)
	if rule := firstArgumentViolation(arguments, policy.ArgumentRules); rule != "" {
		reason := fmt.Sprintf("Argument violated rule: %s", rule)
		if policy.Mode == ModeEnforce {
			return Decision{Action: ActionDeny, Reason: reason}
		}
		return Decision{Action: ActionMonitor, Reason: reason}
	}
	return decision
}

func baseDecision(toolName string, policy Policy) Decision {
	for _, tool := range policy.Tools {
		if tool.Name == toolName {
			reason := tool.Reason
			if reason == "" {
				reason = fmt.Sprintf("tool %q is %s by policy", tool.Name, tool.Action)
			}
			return Decision{Action: tool.Action, Reason: reason}
		}
	}
	return Decision{
		Action: policy.DefaultAction,
		Reason: fmt.Sprintf("default action is %s", policy.DefaultAction),
	}
}

func firstArgumentViolation(arguments map[string]any, rules ArgumentRules) string {
	if arguments == nil {
		return ""
	}
	var found string
	walkStrings(arguments, func(value string) bool {
		if rules.BlockPathTraversal && isPathTraversal(value) {
			found = RulePathTraversal
			return true
		}
		if rules.BlockShellMetacharacters && isShellInjection(value) {
			found = RuleShellMetacharacters
			return true
		}
		if rules.BlockCloudMetadata && isCloudMetadata(value) {
			found = RuleCloudMetadata
			return true
		}
		return false
	})
	return found
}

func walkStrings(v any, fn func(string) bool) bool {
	switch x := v.(type) {
	case nil:
		return false
	case string:
		return fn(x)
	case map[string]any:
		for _, child := range x {
			if walkStrings(child, fn) {
				return true
			}
		}
	case map[any]any:
		for _, child := range x {
			if walkStrings(child, fn) {
				return true
			}
		}
	case []any:
		for _, child := range x {
			if walkStrings(child, fn) {
				return true
			}
		}
	case []string:
		for _, child := range x {
			if fn(child) {
				return true
			}
		}
	}
	return false
}

func inspectionVariants(s string) []string {
	variants := []string{s, strings.ToLower(s)}
	cur := s
	for i := 0; i < 3; i++ {
		decoded, err := url.PathUnescape(cur)
		if err != nil || decoded == cur {
			break
		}
		variants = append(variants, decoded, strings.ToLower(decoded))
		cur = decoded
	}
	return variants
}

func isPathTraversal(s string) bool {
	for _, candidate := range inspectionVariants(s) {
		lower := strings.ToLower(candidate)
		switch {
		case strings.Contains(candidate, "../"),
			strings.Contains(candidate, `..\`),
			strings.Contains(lower, "..%2f"),
			strings.Contains(lower, "%2e%2e%2f"),
			strings.Contains(lower, "%2e%2e/"),
			strings.Contains(lower, "/etc/passwd"),
			unixAbsPathPattern.MatchString(candidate):
			return true
		}
	}
	return false
}

func isShellInjection(s string) bool {
	for _, candidate := range inspectionVariants(s) {
		if strings.Contains(candidate, ";") ||
			strings.Contains(candidate, "&&") ||
			strings.Contains(candidate, "||") ||
			strings.Contains(candidate, "|") ||
			strings.Contains(candidate, "`") ||
			strings.Contains(candidate, "$(") ||
			shellCommandPattern.MatchString(candidate) {
			return true
		}
	}
	return false
}

func isCloudMetadata(s string) bool {
	for _, candidate := range inspectionVariants(s) {
		lower := strings.ToLower(candidate)
		if strings.Contains(lower, "169.254.169.254") || strings.Contains(lower, "metadata.google.internal") {
			return true
		}
	}
	return false
}
