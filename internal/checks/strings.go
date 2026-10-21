package checks

import (
	"os"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/Kumar-ranjan12345/magpie/internal/binary"
	"github.com/Kumar-ranjan12345/magpie/internal/bundle"
	"github.com/Kumar-ranjan12345/magpie/internal/scan"
)

type secretPattern struct {
	name string
	re   *regexp.Regexp
	rule Rule
}

func secretRule(id, title string, sev scan.Severity, desc, fix string) Rule {
	return Rule{ID: id, Title: title, Severity: sev, Category: "Secrets", MASVS: "MASVS-STORAGE-1", Description: desc, Remediation: fix}
}

const rotate = "Remove it from the app, rotate (revoke and reissue) it now, and move the call that needs it to your backend."

var (
	rulePrivateKey = secretRule("MP-SEC-001", "Private key embedded in the app", scan.Critical,
		"A PEM private key was found. Anyone with the IPA can extract it.", rotate)
	ruleCloudKey = secretRule("MP-SEC-002", "Cloud provider credentials embedded", scan.Critical,
		"Long-lived cloud credentials can give an attacker direct access to your cloud account, storage and billing.", rotate)
	rulePaymentKey = secretRule("MP-SEC-003", "Live payment secret key embedded", scan.Critical,
		"A secret (not publishable) payment key lets an attacker issue refunds, read customers and move money.", rotate)
	ruleServiceToken = secretRule("MP-SEC-004", "Service API token embedded", scan.High,
		"Tokens for GitHub, Slack, OpenAI, Twilio, SendGrid and similar services grant account access and can run up bills.", rotate)
	ruleGoogleKey = secretRule("MP-SEC-005", "Google API key embedded", scan.Low,
		"Google API keys in apps are common (Maps, Firebase) and not secret by design, but an unrestricted key can be abused for quota and billing.",
		"Restrict the key to your iOS bundle ID and to only the APIs it needs in Google Cloud Console.")
	ruleJWT = secretRule("MP-SEC-006", "JSON Web Token embedded", scan.Medium,
		"A hard-coded JWT may be a long-lived access token or a test token that still works against your API.",
		"Remove hard-coded tokens. Fetch tokens at runtime after authentication and store them in the Keychain.")
	ruleCleartextURL = Rule{
		ID: "MP-NET-010", Title: "Cleartext HTTP URLs in the app", Severity: scan.Low,
		Category: "Network", MASVS: "MASVS-NETWORK-1",
		Description: "These http:// URLs send data unencrypted if the app ever calls them (ATS may block them unless an exception allows it).",
		Remediation: "Switch these endpoints to https://. Remove URLs that are no longer used.",
	}
	ruleLocalEndpoint = Rule{
		ID: "MP-CODE-001", Title: "Local, private or staging endpoints left in the build", Severity: scan.Low,
		Category: "Code quality", MASVS: "MASVS-CODE-1",
		Description: "localhost, private IP or staging URLs suggest debug configuration shipped in the build, and reveal internal infrastructure.",
		Remediation: "Use build configurations (xcconfig per scheme) so Release builds only contain production endpoints.",
	}
)

var stringRules = []Rule{rulePrivateKey, ruleCloudKey, rulePaymentKey, ruleServiceToken, ruleGoogleKey, ruleJWT, ruleCleartextURL, ruleLocalEndpoint}

var secretPatterns = []secretPattern{
	{"PEM private key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----`), rulePrivateKey},
	{"AWS access key ID", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), ruleCloudKey},
	{"Google Cloud service account", regexp.MustCompile(`"type"\s*:\s*"service_account"`), ruleCloudKey},
	{"Stripe secret key", regexp.MustCompile(`\b[sr]k_live_[0-9A-Za-z]{20,}\b`), rulePaymentKey},
	{"Razorpay key secret", regexp.MustCompile(`\brzp_live_[0-9A-Za-z]{14,}\b`), rulePaymentKey},
	{"GitHub token", regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b|\bgithub_pat_[0-9A-Za-z_]{82}\b`), ruleServiceToken},
	{"Slack token", regexp.MustCompile(`\bxox[abpors]-[0-9A-Za-z-]{10,}\b`), ruleServiceToken},
	{"Slack webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+`), ruleServiceToken},
	{"OpenAI API key", regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b`), ruleServiceToken},
	{"Anthropic API key", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{32,}\b`), ruleServiceToken},
	{"Twilio API key", regexp.MustCompile(`\bSK[0-9a-f]{32}\b`), ruleServiceToken},
	{"SendGrid API key", regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b`), ruleServiceToken},
	{"Google API key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`), ruleGoogleKey},
	{"JWT", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`), ruleJWT},
}

var (
	httpURL  = regexp.MustCompile(`http://[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?::\d+)?(?:/[^\s"'<>\\]*)?`)
	localURL = regexp.MustCompile(`https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|[A-Za-z0-9-]+\.(?:local|internal)|(?:[A-Za-z0-9-]+\.)*(?:staging|stage|stg|dev|qa|uat)[.-][A-Za-z0-9.-]+)(?::\d+)?(?:/[^\s"'<>\\]*)?`)
)

// Well-known namespace and documentation URLs that are never fetched.
var benignHTTP = []string{
	"http://www.apple.com/", "http://www.w3.org/", "http://ns.adobe.com/", "http://schemas.",
	"http://purl.org/", "http://json-schema.org/", "http://www.xml.org/", "http://xml.org/",
	"http://iptc.org/", "http://www.iec.ch", "http://www.color.org", "http://crl.apple.com/",
	"http://ocsp.apple.com/", "http://certs.apple.com/", "http://www.openssl.org/", "http://example.com",
	"http://www.example.com", "http://www.google.com/schemas", "http://www.opengis.net",
}

// Bundled files worth scanning as text. Images, fonts and compiled assets are skipped.
var textExts = map[string]bool{
	".plist": true, ".json": true, ".js": true, ".html": true, ".htm": true, ".xml": true, ".txt": true,
	".strings": true, ".cfg": true, ".conf": true, ".config": true, ".env": true, ".yaml": true, ".yml": true,
	".properties": true, ".ini": true, ".pem": true, ".key": true,
}

const maxTextFile = 5 << 20

type source struct {
	where   string
	strings []string
}

func stringChecks(app *bundle.App) []scan.Finding {
	var sources []source
	if !app.Binary.Encrypted {
		sources = append(sources, source{"binary", app.Binary.Strings(8)})
	}
	for _, f := range app.Files {
		name := path.Base(f.Rel)
		ext := strings.ToLower(path.Ext(name))
		if !textExts[ext] && !strings.HasPrefix(name, ".env") || f.Size > maxTextFile {
			continue
		}
		if name == "GoogleService-Info.plist" { // reported by MP-NET-009 instead
			continue
		}
		data, err := os.ReadFile(f.Abs)
		if err != nil {
			continue
		}
		sources = append(sources, source{f.Rel, binary.Strings(data, 8)})
	}

	hits := map[string][]string{}
	rules := map[string]Rule{}
	seen := map[string]bool{}
	add := func(r Rule, ev string) {
		if seen[r.ID+ev] {
			return
		}
		seen[r.ID+ev] = true
		hits[r.ID] = append(hits[r.ID], ev)
		rules[r.ID] = r
	}

	for _, src := range sources {
		for _, s := range src.strings {
			for _, p := range secretPatterns {
				for _, m := range p.re.FindAllString(s, -1) {
					add(p.rule, p.name+": "+redact(m)+" ("+src.where+")")
				}
			}
			for _, m := range localURL.FindAllString(s, -1) {
				add(ruleLocalEndpoint, m+" ("+src.where+")")
			}
			for _, m := range httpURL.FindAllString(s, -1) {
				if !isBenignHTTP(m) && !localURL.MatchString(m) {
					add(ruleCleartextURL, m+" ("+src.where+")")
				}
			}
		}
	}

	var out []scan.Finding
	for id, ev := range hits {
		sort.Strings(ev)
		out = append(out, rules[id].finding(ev...))
	}
	return out
}

func isBenignHTTP(u string) bool {
	for _, p := range benignHTTP {
		if strings.HasPrefix(u, p) {
			return true
		}
	}
	return false
}

// redact keeps enough of a secret to identify it without reprinting it in full.
func redact(s string) string {
	if strings.HasPrefix(s, "-----") || strings.HasPrefix(s, `"type"`) || strings.HasPrefix(s, "https://") {
		if len(s) > 48 {
			return s[:48] + "…"
		}
		return s
	}
	if len(s) <= 12 {
		return s[:4] + "…"
	}
	return s[:8] + "…" + s[len(s)-4:]
}
