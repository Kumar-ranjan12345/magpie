// Package checks contains the security rules. Each rule describes one issue;
// each check function inspects part of the app and reports the rules it trips.
package checks

import (
	"strconv"

	"github.com/Kumar-ranjan12345/magpie/internal/bundle"
	"github.com/Kumar-ranjan12345/magpie/internal/scan"
)

// Rule is the static description of an issue. Findings copy it and add evidence.
type Rule struct {
	ID          string
	Title       string
	Severity    scan.Severity
	Category    string
	MASVS       string
	Description string
	Remediation string
}

// maxEvidence keeps reports readable when a rule matches hundreds of times.
const maxEvidence = 10

func (r Rule) finding(evidence ...string) scan.Finding {
	if len(evidence) > maxEvidence {
		extra := len(evidence) - maxEvidence
		evidence = append(evidence[:maxEvidence:maxEvidence], pluralMore(extra))
	}
	return scan.Finding{
		ID:          r.ID,
		Title:       r.Title,
		Severity:    r.Severity,
		Category:    r.Category,
		MASVS:       r.MASVS,
		Description: r.Description,
		Remediation: r.Remediation,
		Evidence:    evidence,
	}
}

func pluralMore(n int) string {
	if n == 1 {
		return "…and 1 more"
	}
	return "…and " + strconv.Itoa(n) + " more"
}

type check func(*bundle.App) []scan.Finding

var all = []check{
	binaryChecks,
	transportChecks,
	plistChecks,
	entitlementChecks,
	fileChecks,
	stringChecks,
	resilienceChecks,
}

// Run applies every check to the app.
func Run(app *bundle.App) []scan.Finding {
	var out []scan.Finding
	for _, c := range all {
		out = append(out, c(app)...)
	}
	return out
}

// Rules lists every rule, for documentation and the `rules` command.
func Rules() []Rule {
	var out []Rule
	for _, group := range [][]Rule{binaryRules, transportRules, plistRules, entitlementRules, fileRules, stringRules, resilienceRules} {
		out = append(out, group...)
	}
	return out
}
