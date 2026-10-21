package checks

import (
	"fmt"
	"strings"

	"github.com/Kumar-ranjan12345/magpie/internal/bundle"
	"github.com/Kumar-ranjan12345/magpie/internal/scan"
)

var (
	ruleDebuggable = Rule{
		ID: "MP-ENT-001", Title: "App is debuggable (get-task-allow)", Severity: scan.High,
		Category: "Resilience", MASVS: "MASVS-RESILIENCE-4",
		Description: "The get-task-allow entitlement lets a debugger attach to the app, so memory, keys and tokens can be read at runtime. It should only appear in Development builds.",
		Remediation: "Ship with a Distribution (App Store, Ad Hoc or Enterprise) provisioning profile, which sets get-task-allow to false.",
	}
	ruleDevPush = Rule{
		ID: "MP-ENT-002", Title: "Development push environment", Severity: scan.Low,
		Category: "Platform", MASVS: "MASVS-CODE-1",
		Description: "aps-environment is 'development', which means this is not a production build. Push notifications from the production APNs server will not arrive.",
		Remediation: "Archive with a Distribution profile so aps-environment is 'production'.",
	}
	ruleKeychainWildcard = Rule{
		ID: "MP-ENT-003", Title: "Keychain access group uses a wildcard", Severity: scan.Medium,
		Category: "Storage", MASVS: "MASVS-STORAGE-1",
		Description: "A wildcard keychain-access-groups entry shares keychain items more widely than needed.",
		Remediation: "List explicit access groups (TeamID.com.example.shared) instead of a wildcard.",
	}
	ruleNoEntitlements = Rule{
		ID: "MP-ENT-004", Title: "No code signature entitlements found", Severity: scan.Info,
		Category: "Scan coverage", MASVS: "",
		Description: "The executable is unsigned or the signature has no entitlements blob, so entitlement checks were skipped. This is normal for Simulator builds.",
		Remediation: "Scan a signed device build (Xcode → Archive → Distribute App) for full coverage.",
	}
)

var entitlementRules = []Rule{ruleDebuggable, ruleDevPush, ruleKeychainWildcard, ruleNoEntitlements}

func entitlementChecks(app *bundle.App) []scan.Finding {
	ent := app.Entitlements
	if ent == nil {
		return []scan.Finding{ruleNoEntitlements.finding()}
	}
	var out []scan.Finding
	if isTrue(ent["get-task-allow"]) {
		out = append(out, ruleDebuggable.finding("get-task-allow = true"))
	}
	if env, _ := ent["aps-environment"].(string); env == "development" {
		out = append(out, ruleDevPush.finding("aps-environment = development"))
	}
	groups, _ := ent["keychain-access-groups"].([]any)
	var wild []string
	for _, g := range groups {
		if s, ok := g.(string); ok && strings.Contains(s, "*") {
			wild = append(wild, fmt.Sprintf("keychain-access-groups → %s", s))
		}
	}
	if len(wild) > 0 {
		out = append(out, ruleKeychainWildcard.finding(wild...))
	}
	return out
}
