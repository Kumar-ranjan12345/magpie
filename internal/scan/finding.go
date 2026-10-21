// Package scan holds the types shared by the checks and the reporters:
// severities, findings and the final report with its grade.
package scan

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var severityNames = []string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < Info || s > Critical {
		return "unknown"
	}
	return severityNames[s]
}

func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func ParseSeverity(v string) (Severity, error) {
	for i, n := range severityNames {
		if strings.EqualFold(v, n) {
			return Severity(i), nil
		}
	}
	return Info, fmt.Errorf("unknown severity %q (want one of %s)", v, strings.Join(severityNames, ", "))
}

// Finding is one issue found in the app, with enough context for a developer to fix it.
type Finding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    Severity `json:"severity"`
	Category    string   `json:"category"`
	MASVS       string   `json:"masvs"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation"`
	Evidence    []string `json:"evidence,omitempty"`
}
