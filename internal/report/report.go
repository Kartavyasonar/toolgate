package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/kartavyasonar/toolgate/internal/scanner"
)

type Format string

const (
	FormatText     Format = "text"
	FormatJSON     Format = "json"
	FormatMarkdown Format = "markdown"
)

func ParseFormat(s string) (Format, error) {
	switch Format(strings.ToLower(strings.TrimSpace(s))) {
	case FormatText:
		return FormatText, nil
	case FormatJSON:
		return FormatJSON, nil
	case FormatMarkdown:
		return FormatMarkdown, nil
	default:
		return "", fmt.Errorf("unsupported format %q", s)
	}
}

type Report struct {
	Target string
	Result scanner.ScoreResult
}

func New(target string, result scanner.ScoreResult) Report {
	return Report{Target: target, Result: result}
}

func (r Report) Render(format Format) (string, error) {
	switch format {
	case FormatText:
		return r.renderText(), nil
	case FormatJSON:
		return r.renderJSON()
	case FormatMarkdown:
		return r.renderMarkdown(), nil
	default:
		return "", fmt.Errorf("unsupported format %q", format)
	}
}

func (r Report) renderText() string {
	var b strings.Builder
	fmt.Fprintln(&b, "ToolGate Scan Report")
	fmt.Fprintf(&b, "Target: %s\n", r.Target)
	fmt.Fprintf(&b, "Score:  %d/100 (%s)\n", r.Result.Score, r.Result.Rating)
	fmt.Fprintln(&b)

	if len(r.Result.Findings) == 0 {
		fmt.Fprintln(&b, "Findings: none")
		return strings.TrimRight(b.String(), "\n")
	}

	fmt.Fprintf(&b, "Findings (%d):\n", len(r.Result.Findings))
	for _, f := range r.Result.Findings {
		fmt.Fprintf(&b, "  [%s] %s: %s\n", f.Rule, f.Tool, f.Message)
	}

	if rules := sortedRules(r.Result.Deductions); len(rules) > 0 {
		fmt.Fprintln(&b)
		fmt.Fprintln(&b, "Deductions:")
		for _, rule := range rules {
			fmt.Fprintf(&b, "  %s: -%d\n", rule, r.Result.Deductions[rule])
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

type jsonFinding struct {
	Tool    string `json:"tool"`
	Rule    string `json:"rule"`
	Message string `json:"message"`
}

type jsonDeduction struct {
	Rule   string `json:"rule"`
	Points int    `json:"points"`
}

type jsonReport struct {
	Target        string          `json:"target"`
	Score         int             `json:"score"`
	Rating        string          `json:"rating"`
	FindingsCount int             `json:"findings_count"`
	Findings      []jsonFinding   `json:"findings"`
	Deductions    []jsonDeduction `json:"deductions"`
}

func (r Report) renderJSON() (string, error) {
	findings := make([]jsonFinding, 0, len(r.Result.Findings))
	for _, f := range r.Result.Findings {
		findings = append(findings, jsonFinding{
			Tool:    f.Tool,
			Rule:    f.Rule,
			Message: f.Message,
		})
	}

	rules := sortedRules(r.Result.Deductions)
	deductions := make([]jsonDeduction, 0, len(rules))
	for _, rule := range rules {
		deductions = append(deductions, jsonDeduction{
			Rule:   rule,
			Points: r.Result.Deductions[rule],
		})
	}

	jr := jsonReport{
		Target:        r.Target,
		Score:         r.Result.Score,
		Rating:        r.Result.Rating,
		FindingsCount: len(r.Result.Findings),
		Findings:      findings,
		Deductions:    deductions,
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(jr); err != nil {
		return "", fmt.Errorf("encoding report as json: %w", err)
	}
	return strings.TrimRight(buf.String(), "\n"), nil
}

func (r Report) renderMarkdown() string {
	var b strings.Builder
	fmt.Fprintln(&b, "# ToolGate Scan Report")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "**Target:** `%s`\n\n", r.Target)
	fmt.Fprintf(&b, "**Score:** %d/100 (**%s**)\n\n", r.Result.Score, r.Result.Rating)

	if len(r.Result.Findings) == 0 {
		fmt.Fprintln(&b, "No findings.")
		return strings.TrimRight(b.String(), "\n")
	}

	fmt.Fprintf(&b, "## Findings (%d)\n\n", len(r.Result.Findings))
	fmt.Fprintln(&b, "| Tool | Rule | Message |")
	fmt.Fprintln(&b, "| --- | --- | --- |")
	for _, f := range r.Result.Findings {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", f.Tool, f.Rule, f.Message)
	}

	if rules := sortedRules(r.Result.Deductions); len(rules) > 0 {
		fmt.Fprintln(&b)
		fmt.Fprintln(&b, "## Deductions")
		fmt.Fprintln(&b)
		fmt.Fprintln(&b, "| Rule | Points |")
		fmt.Fprintln(&b, "| --- | --- |")
		for _, rule := range rules {
			fmt.Fprintf(&b, "| %s | -%d |\n", rule, r.Result.Deductions[rule])
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func sortedRules(m map[string]int) []string {
	rules := make([]string, 0, len(m))
	for k := range m {
		rules = append(rules, k)
	}
	sort.Strings(rules)
	return rules
}