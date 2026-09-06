package scanner

import "sort"

var deductions = map[string]int{
	"missing_schema":         15,
	"permissive_schema":      10,
	"suspicious_description": 10,
	"dangerous_tool_name":    20,
}

const (
	maxScore = 100
	minScore = 0
)

type ScoreResult struct {
	Score      int
	Rating     string
	Findings   []Finding
	Deductions map[string]int
}

func Score(findings []Finding) ScoreResult {
	score := maxScore
	perRule := make(map[string]int)

	for _, f := range findings {
		penalty, known := deductions[f.Rule]
		if !known {
			continue
		}
		score -= penalty
		perRule[f.Rule] += penalty
	}

	if score < minScore {
		score = minScore
	}

	kept := make([]Finding, len(findings))
	copy(kept, findings)

	return ScoreResult{
		Score:      score,
		Rating:     Rating(score),
		Findings:   kept,
		Deductions: perRule,
	}
}

func Rating(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

func SortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Tool != findings[j].Tool {
			return findings[i].Tool < findings[j].Tool
		}
		return findings[i].Rule < findings[j].Rule
	})
}