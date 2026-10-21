package checks

import (
	"fmt"
	"sort"

	"github.com/Kumar-ranjan12345/magpie/internal/bundle"
	"github.com/Kumar-ranjan12345/magpie/internal/scan"
)

var (
	ruleATSDisabled = Rule{
		ID: "MP-NET-001", Title: "App Transport Security disabled for all connections", Severity: scan.High,
		Category: "Network", MASVS: "MASVS-NETWORK-1",
		Description: "NSAllowsArbitraryLoads is true, so the app may load any URL over plain HTTP or weak TLS. Traffic can be read or modified on public Wi-Fi.",
		Remediation: "Remove NSAllowsArbitraryLoads. If one legacy host needs HTTP, add a narrow NSExceptionDomains entry for just that host, and plan to move it to HTTPS.",
	}
	ruleATSWebContent = Rule{
		ID: "MP-NET-002", Title: "App Transport Security disabled for web content", Severity: scan.Medium,
		Category: "Network", MASVS: "MASVS-NETWORK-1",
		Description: "NSAllowsArbitraryLoadsInWebContent lets WKWebView load insecure pages. Anything shown or entered there can be intercepted.",
		Remediation: "Remove the key unless the app is a general-purpose browser. Load only HTTPS content in web views.",
	}
	ruleATSMedia = Rule{
		ID: "MP-NET-003", Title: "App Transport Security disabled for media", Severity: scan.Low,
		Category: "Network", MASVS: "MASVS-NETWORK-1",
		Description: "NSAllowsArbitraryLoadsForMedia lets AVFoundation stream media over insecure connections.",
		Remediation: "Serve media over HTTPS and remove the key, unless the media is already protected (for example with FairPlay Streaming).",
	}
	ruleATSInsecureDomain = Rule{
		ID: "MP-NET-004", Title: "Plain HTTP allowed for specific domains", Severity: scan.Medium,
		Category: "Network", MASVS: "MASVS-NETWORK-1",
		Description: "NSExceptionAllowsInsecureHTTPLoads allows unencrypted HTTP to these domains. Requests and responses can be read or tampered with.",
		Remediation: "Move these hosts to HTTPS and remove the exception.",
	}
	ruleATSOldTLS = Rule{
		ID: "MP-NET-005", Title: "Outdated TLS version allowed for specific domains", Severity: scan.Medium,
		Category: "Network", MASVS: "MASVS-NETWORK-1",
		Description: "NSExceptionMinimumTLSVersion is below TLS 1.2 for these domains. TLS 1.0 and 1.1 are deprecated and have known weaknesses.",
		Remediation: "Require TLSv1.2 or later (the ATS default) and upgrade the server if needed.",
	}
	ruleATSNoPFS = Rule{
		ID: "MP-NET-006", Title: "Forward secrecy not required for specific domains", Severity: scan.Low,
		Category: "Network", MASVS: "MASVS-NETWORK-1",
		Description: "NSExceptionRequiresForwardSecrecy is false, so recorded traffic could be decrypted later if the server key leaks.",
		Remediation: "Enable ECDHE cipher suites on the server and remove the exception.",
	}
	ruleATSLocal = Rule{
		ID: "MP-NET-007", Title: "Insecure local-network connections allowed", Severity: scan.Info,
		Category: "Network", MASVS: "MASVS-NETWORK-1",
		Description: "NSAllowsLocalNetworking allows plain HTTP to local hosts and .local names. Usually fine for device-pairing apps; check that it's intended.",
		Remediation: "Keep it only if the app talks to devices on the local network.",
	}
)

var transportRules = []Rule{ruleATSDisabled, ruleATSWebContent, ruleATSMedia, ruleATSInsecureDomain, ruleATSOldTLS, ruleATSNoPFS, ruleATSLocal}

func transportChecks(app *bundle.App) []scan.Finding {
	ats, _ := app.Info["NSAppTransportSecurity"].(map[string]any)
	if ats == nil {
		return nil
	}
	var out []scan.Finding
	flag := func(key string, rule Rule) {
		if isTrue(ats[key]) {
			out = append(out, rule.finding(fmt.Sprintf("Info.plist → NSAppTransportSecurity → %s = true", key)))
		}
	}
	flag("NSAllowsArbitraryLoads", ruleATSDisabled)
	flag("NSAllowsArbitraryLoadsInWebContent", ruleATSWebContent)
	flag("NSAllowsArbitraryLoadsForMedia", ruleATSMedia)
	flag("NSAllowsLocalNetworking", ruleATSLocal)

	domains, _ := ats["NSExceptionDomains"].(map[string]any)
	names := make([]string, 0, len(domains))
	for d := range domains {
		names = append(names, d)
	}
	sort.Strings(names)

	var insecure, oldTLS, noPFS []string
	for _, d := range names {
		cfg, _ := domains[d].(map[string]any)
		if cfg == nil {
			continue
		}
		label := d
		if isTrue(cfg["NSIncludesSubdomains"]) {
			label += " (and subdomains)"
		}
		if isTrue(cfg["NSExceptionAllowsInsecureHTTPLoads"]) || isTrue(cfg["NSThirdPartyExceptionAllowsInsecureHTTPLoads"]) {
			insecure = append(insecure, label)
		}
		for _, k := range []string{"NSExceptionMinimumTLSVersion", "NSThirdPartyExceptionMinimumTLSVersion"} {
			if v, _ := cfg[k].(string); v == "TLSv1.0" || v == "TLSv1.1" {
				oldTLS = append(oldTLS, fmt.Sprintf("%s → %s", label, v))
			}
		}
		for _, k := range []string{"NSExceptionRequiresForwardSecrecy", "NSThirdPartyExceptionRequiresForwardSecrecy"} {
			if isFalse(cfg[k]) {
				noPFS = append(noPFS, label)
				break
			}
		}
	}
	if len(insecure) > 0 {
		out = append(out, ruleATSInsecureDomain.finding(insecure...))
	}
	if len(oldTLS) > 0 {
		out = append(out, ruleATSOldTLS.finding(oldTLS...))
	}
	if len(noPFS) > 0 {
		out = append(out, ruleATSNoPFS.finding(noPFS...))
	}
	return out
}

func isTrue(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string: // some hand-edited plists store booleans as strings
		return t == "YES" || t == "true" || t == "1"
	}
	return false
}

func isFalse(v any) bool {
	switch t := v.(type) {
	case bool:
		return !t
	case string:
		return t == "NO" || t == "false" || t == "0"
	}
	return false
}
