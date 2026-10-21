package checks

import (
	"path"
	"sort"
	"strings"

	"github.com/Kumar-ranjan12345/magpie/internal/bundle"
	"github.com/Kumar-ranjan12345/magpie/internal/scan"
)

var (
	rulePrivateKeyFile = Rule{
		ID: "MP-STG-002", Title: "Private key or keystore file bundled in the app", Severity: scan.Critical,
		Category: "Storage", MASVS: "MASVS-CRYPTO-2",
		Description: "Files such as .p12, .pfx, .pem and .key usually hold private keys. Anyone who downloads the app can extract them and impersonate your client or server.",
		Remediation: "Remove the file from the target and rotate the key. Client identities should be provisioned at runtime and stored in the Keychain, never shipped in the bundle.",
	}
	ruleDatabaseFile = Rule{
		ID: "MP-STG-003", Title: "Database or config files bundled in the app", Severity: scan.Low,
		Category: "Storage", MASVS: "MASVS-STORAGE-1",
		Description: "Bundled SQLite/Realm databases and .env or config files are readable by anyone with the IPA. Check that they hold no user data, credentials or internal endpoints.",
		Remediation: "Ship only data that is meant to be public. Keep secrets on the server and fetch per-user data after login.",
	}
	ruleSourceFile = Rule{
		ID: "MP-CODE-002", Title: "Source code or build artefacts bundled in the app", Severity: scan.Low,
		Category: "Code quality", MASVS: "MASVS-CODE-1",
		Description: "Source files or build scripts were copied into the app by mistake, usually via 'Copy Bundle Resources'. They can reveal implementation details.",
		Remediation: "Remove them from the target's Copy Bundle Resources build phase.",
	}
	ruleCertificates = Rule{
		ID: "MP-NET-008", Title: "Certificates bundled (likely used for pinning)", Severity: scan.Info,
		Category: "Network", MASVS: "MASVS-NETWORK-2",
		Description: "Bundled .cer/.der/.crt files usually mean certificate pinning, which is good. Make sure pinning is enforced in code and there is a backup pin for rotation.",
		Remediation: "Pin the public key (SPKI) rather than the whole certificate, and include at least one backup key.",
	}
	ruleFirebaseConfig = Rule{
		ID: "MP-NET-009", Title: "Firebase / Google service config bundled", Severity: scan.Info,
		Category: "Network", MASVS: "MASVS-NETWORK-1",
		Description: "GoogleService-Info.plist contains an API key and project IDs. That is expected, but the key must be restricted and Firebase security rules must not allow public read/write.",
		Remediation: "Restrict the API key to your bundle ID in Google Cloud Console, and review Firestore, Realtime Database and Storage security rules.",
	}
)

var fileRules = []Rule{rulePrivateKeyFile, ruleDatabaseFile, ruleSourceFile, ruleCertificates, ruleFirebaseConfig}

var fileExtRules = map[string]Rule{
	".p12": rulePrivateKeyFile, ".pfx": rulePrivateKeyFile, ".pem": rulePrivateKeyFile,
	".key": rulePrivateKeyFile, ".jks": rulePrivateKeyFile, ".keystore": rulePrivateKeyFile,
	".sqlite": ruleDatabaseFile, ".sqlite3": ruleDatabaseFile, ".db": ruleDatabaseFile, ".realm": ruleDatabaseFile,
	".env": ruleDatabaseFile, ".yaml": ruleDatabaseFile, ".yml": ruleDatabaseFile, ".properties": ruleDatabaseFile,
	".swift": ruleSourceFile, ".m": ruleSourceFile, ".mm": ruleSourceFile, ".c": ruleSourceFile, ".cpp": ruleSourceFile,
	".h": ruleSourceFile, ".sh": ruleSourceFile, ".py": ruleSourceFile, ".xcconfig": ruleSourceFile,
	".cer": ruleCertificates, ".der": ruleCertificates, ".crt": ruleCertificates,
}

func fileChecks(app *bundle.App) []scan.Finding {
	hits := map[string][]string{}
	rules := map[string]Rule{}
	add := func(r Rule, file string) {
		hits[r.ID] = append(hits[r.ID], file)
		rules[r.ID] = r
	}

	for _, f := range app.Files {
		name := path.Base(f.Rel)
		// Headers inside frameworks are normal; only flag ones in the app itself.
		if strings.Contains(f.Rel, ".framework/") && path.Ext(name) == ".h" {
			continue
		}
		if name == "GoogleService-Info.plist" {
			add(ruleFirebaseConfig, f.Rel)
			continue
		}
		ext := strings.ToLower(path.Ext(name))
		if name == ".env" || strings.HasPrefix(name, ".env.") {
			ext = ".env"
		}
		if r, ok := fileExtRules[ext]; ok {
			add(r, f.Rel)
		}
	}

	var out []scan.Finding
	for id, files := range hits {
		sort.Strings(files)
		out = append(out, rules[id].finding(files...))
	}
	return out
}
