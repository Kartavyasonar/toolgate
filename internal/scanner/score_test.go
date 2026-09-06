package scanner

import (
	"fmt"
	"reflect"
	"testing"
)

func TestScore(t *testing.T) {
	tests := []struct {
		name           string
		findings       []Finding
		wantScore      int
		wantRating     string
		wantDeductions map[string]int
	}{
		{
			name:           "no findings scores perfect",
			findings:       nil,
			wantScore:      100,
			wantRating:     "A",
			wantDeductions: map[string]int{},
		},
		{
			name: "single missing schema",
			findings: []Finding{
				{Tool: "fetch_url", Rule: "missing_schema"},
			},
			wantScore:      85,
			wantRating:     "B",
			wantDeductions: map[string]int{"missing_schema": 15},
		},
		{
			name: "multiple findings",
			findings: []Finding{
				{Tool: "delete_all", Rule: "dangerous_tool_name"},
				{Tool: "delete_all", Rule: "missing_schema"},
				{Tool: "fetch_url", Rule: "permissive_schema"},
			},
			wantScore:  55,
			wantRating: "F",
			wantDeductions: map[string]int{
				"dangerous_tool_name": 20,
				"missing_schema":      15,
				"permissive_schema":   10,
			},
		},
		{
			name: "score clamps at zero",
			findings: []Finding{
				{Tool: "a", Rule: "dangerous_tool_name"},
				{Tool: "b", Rule: "dangerous_tool_name"},
				{Tool: "c", Rule: "dangerous_tool_name"},
				{Tool: "d", Rule: "dangerous_tool_name"},
				{Tool: "e", Rule: "dangerous_tool_name"},
				{Tool: "f", Rule: "dangerous_tool_name"},
			},
			wantScore:      0,
			wantRating:     "F",
			wantDeductions: map[string]int{"dangerous_tool_name": 120},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Score(tt.findings)
			if got.Score != tt.wantScore {
				t.Errorf("Score = %d, want %d", got.Score, tt.wantScore)
			}
			if got.Rating != tt.wantRating {
				t.Errorf("Rating = %s, want %s", got.Rating, tt.wantRating)
			}
			if !reflect.DeepEqual(got.Deductions, tt.wantDeductions) {
				t.Errorf("Deductions = %#v, want %#v", got.Deductions, tt.wantDeductions)
			}
		})
	}
}

func TestRatingBoundaries(t *testing.T) {
	tests := []struct {
		score int
		want  string
	}{
		{100, "A"}, {90, "A"}, {89, "B"}, {80, "B"}, {79, "C"},
		{70, "C"}, {69, "D"}, {60, "D"}, {59, "F"}, {0, "F"}, {-10, "F"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("score_%d", tt.score), func(t *testing.T) {
			if got := Rating(tt.score); got != tt.want {
				t.Errorf("Rating(%d) = %s, want %s", tt.score, got, tt.want)
			}
		})
	}
}

func TestSortFindings(t *testing.T) {
	findings := []Finding{
		{Tool: "zeta", Rule: "missing_schema"},
		{Tool: "alpha", Rule: "dangerous_tool_name"},
		{Tool: "alpha", Rule: "missing_schema"},
	}
	SortFindings(findings)
	want := []Finding{
		{Tool: "alpha", Rule: "dangerous_tool_name"},
		{Tool: "alpha", Rule: "missing_schema"},
		{Tool: "zeta", Rule: "missing_schema"},
	}
	if !reflect.DeepEqual(findings, want) {
		t.Errorf("SortFindings result = %#v, want %#v", findings, want)
	}
}