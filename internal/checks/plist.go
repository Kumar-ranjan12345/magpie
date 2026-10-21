package checks

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Kumar-ranjan12345/magpie/internal/bundle"
	"github.com/Kumar-ranjan12345/magpie/internal/scan"
)

var (
	ruleURLSchemes = Rule{
		ID: "MP-PLT-001", Title: "Custom URL schemes registered", Severity: scan.Info,
		Category: "Platform", MASVS: "MASVS-PLATFORM-1",
		Description: "Any app can register the same custom scheme and intercept these links, and any web page can open them with arbitrary parameters.",
		Remediation: "Validate every parameter in URL handlers and never trigger sensitive actions from a link without user confirmation. For OAuth or login callbacks prefer Universal Links or ASWebAuthenticationSession.",
	}
	ruleFileSharing = Rule{
		ID: "MP-STG-001", Title: "App's Documents folder exposed via Files / iTunes", Severity: scan.Low,
		Category: "Storage", MASVS: "MASVS-STORAGE-2",
		Description: "UIFileSharingEnabled or LSSupportsOpeningDocumentsInPlace makes the Documents directory visible in the Files app and Finder. Anything stored there can be copied off the device.",
		Remediation: "Keep these off unless sharing documents is a feature. Store private data in Library/Application Support, not Documents.",
	}
	ruleOldMinOS = Rule{
		ID: "MP-PLT-002", Title: "Supports old iOS versions", Severity: scan.Low,
		Category: "Platform", MASVS: "MASVS-CODE-3",
		Description: "The app runs on iOS versions that no longer receive security updates, so users on those devices are exposed to known OS vulnerabilities.",
		Remediation: "Raise the deployment target to a supported iOS version (iOS 16 or later is a reasonable floor today).",
	}
	ruleBackgroundModes = Rule{
		ID: "MP-PRV-001", Title: "Background modes enabled", Severity: scan.Info,
		Category: "Privacy", MASVS: "MASVS-PRIVACY-1",
		Description: "The app can keep running in the background for these purposes. Location and Bluetooth background modes in particular deserve a privacy review.",
		Remediation: "Keep only the background modes the app genuinely needs.",
	}
)

var plistRules = []Rule{ruleURLSchemes, ruleFileSharing, ruleOldMinOS, ruleBackgroundModes}

// minSupportedMajor is the oldest iOS major version still getting security fixes.
const minSupportedMajor = 16

func plistChecks(app *bundle.App) []scan.Finding {
	var out []scan.Finding

	var schemes []string
	types, _ := app.Info["CFBundleURLTypes"].([]any)
	for _, t := range types {
		m, _ := t.(map[string]any)
		list, _ := m["CFBundleURLSchemes"].([]any)
		for _, s := range list {
			if str, ok := s.(string); ok && str != "" {
				schemes = append(schemes, str+"://")
			}
		}
	}
	if len(schemes) > 0 {
		sort.Strings(schemes)
		out = append(out, ruleURLSchemes.finding(schemes...))
	}

	var sharing []string
	for _, k := range []string{"UIFileSharingEnabled", "LSSupportsOpeningDocumentsInPlace"} {
		if isTrue(app.Info[k]) {
			sharing = append(sharing, "Info.plist → "+k+" = true")
		}
	}
	if len(sharing) > 0 {
		out = append(out, ruleFileSharing.finding(sharing...))
	}

	minOS := app.String("MinimumOSVersion")
	if minOS == "" {
		minOS = app.Binary.MinOS
	}
	if major, err := strconv.Atoi(strings.SplitN(minOS, ".", 2)[0]); err == nil && major < minSupportedMajor {
		out = append(out, ruleOldMinOS.finding(fmt.Sprintf("Minimum iOS version: %s", minOS)))
	}

	if modes, _ := app.Info["UIBackgroundModes"].([]any); len(modes) > 0 {
		var ev []string
		for _, m := range modes {
			if s, ok := m.(string); ok {
				ev = append(ev, s)
			}
		}
		sort.Strings(ev)
		out = append(out, ruleBackgroundModes.finding(ev...))
	}
	return out
}
