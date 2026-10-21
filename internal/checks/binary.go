package checks

import (
	"sort"

	"github.com/Kumar-ranjan12345/magpie/internal/bundle"
	"github.com/Kumar-ranjan12345/magpie/internal/scan"
)

var (
	ruleNoPIE = Rule{
		ID: "MP-BIN-001", Title: "Executable is not position independent (no PIE)", Severity: scan.High,
		Category: "Binary hardening", MASVS: "MASVS-CODE-4",
		Description: "Without PIE the executable loads at a fixed address, so ASLR cannot randomise it and memory-corruption exploits become much easier.",
		Remediation: "Build with the default -fPIE / -pie flags. In Xcode, make sure 'Generate Position-Dependent Code' is set to No.",
	}
	ruleNoCanary = Rule{
		ID: "MP-BIN-002", Title: "Stack canaries not detected", Severity: scan.Low,
		Category: "Binary hardening", MASVS: "MASVS-CODE-4",
		Description: "The binary does not reference __stack_chk_guard, so C/Objective-C stack buffer overflows are not caught at runtime. Pure Swift apps often show this harmlessly; it matters if you ship C, C++ or Objective-C code.",
		Remediation: "Compile C and Objective-C code with -fstack-protector-all (or -fstack-protector-strong).",
	}
	ruleNoARC = Rule{
		ID: "MP-BIN-003", Title: "Objective-C code built without ARC", Severity: scan.Medium,
		Category: "Binary hardening", MASVS: "MASVS-CODE-4",
		Description: "The binary uses Objective-C but no ARC runtime calls were found. Manual memory management is prone to use-after-free and double-free bugs.",
		Remediation: "Enable 'Objective-C Automatic Reference Counting' (-fobjc-arc) for all targets.",
	}
	ruleNotStripped = Rule{
		ID: "MP-BIN-004", Title: "Symbols are not stripped", Severity: scan.Low,
		Category: "Resilience", MASVS: "MASVS-RESILIENCE-3",
		Description: "Local symbol names are left in the executable. They make reverse engineering easier by revealing class, function and file names.",
		Remediation: "For Release builds set 'Strip Linked Product' and 'Strip Debug Symbols During Copy' to Yes, and 'Strip Style' to All Symbols (Non-Global for frameworks).",
	}
	ruleDebugInfo = Rule{
		ID: "MP-BIN-005", Title: "Debug information embedded in the executable", Severity: scan.Low,
		Category: "Resilience", MASVS: "MASVS-RESILIENCE-3",
		Description: "DWARF data or a debug map was found in the shipped binary. It can reveal source file paths, types and line numbers.",
		Remediation: "Set 'Debug Information Format' to 'DWARF with dSYM File' for Release so debug info goes into the separate dSYM, not the app.",
	}
	ruleEncrypted = Rule{
		ID: "MP-BIN-006", Title: "Executable is FairPlay-encrypted", Severity: scan.Info,
		Category: "Scan coverage", MASVS: "",
		Description: "This looks like an App Store download: the code is encrypted, so string-based checks (secrets, URLs) could not read the binary. Info.plist, entitlements and bundled files were still scanned.",
		Remediation: "For a full scan, use an Xcode archive export (Ad Hoc, Development or Enterprise) of your own app.",
	}
	ruleUnsafeC = Rule{
		ID: "MP-BIN-007", Title: "Unsafe C string functions imported", Severity: scan.Low,
		Category: "Code quality", MASVS: "MASVS-CODE-4",
		Description: "Functions such as strcpy, strcat, sprintf and gets do no bounds checking and are a classic source of buffer overflows.",
		Remediation: "Use the bounded versions (strlcpy, strlcat, snprintf) or Swift/Foundation string APIs.",
	}
	ruleWeakRandom = Rule{
		ID: "MP-BIN-008", Title: "Insecure random number generator imported", Severity: scan.Medium,
		Category: "Cryptography", MASVS: "MASVS-CRYPTO-1",
		Description: "rand(), random() and srand() are predictable. If they generate tokens, nonces, keys or IVs, an attacker can guess them.",
		Remediation: "Use SecRandomCopyBytes, CryptoKit (SymmetricKey, AES.GCM.Nonce) or SystemRandomNumberGenerator for anything security-related.",
	}
	ruleWeakHash = Rule{
		ID: "MP-BIN-009", Title: "Weak hash algorithm used (MD5 / SHA-1)", Severity: scan.Medium,
		Category: "Cryptography", MASVS: "MASVS-CRYPTO-1",
		Description: "MD5 and SHA-1 are broken for collision resistance. They must not be used for signatures, integrity checks or password hashing.",
		Remediation: "Use SHA-256 or stronger (CryptoKit SHA256/SHA512). For passwords use a slow KDF such as PBKDF2, scrypt or Argon2.",
	}
	ruleWeakCipher = Rule{
		ID: "MP-BIN-010", Title: "Legacy cipher API in use (CommonCrypto CCCrypt)", Severity: scan.Info,
		Category: "Cryptography", MASVS: "MASVS-CRYPTO-1",
		Description: "CCCrypt is easy to misuse: ECB mode, static IVs and DES/3DES are common mistakes. Its presence is worth a manual review.",
		Remediation: "Prefer CryptoKit's AES.GCM or ChaChaPoly, which are authenticated and pick safe defaults.",
	}
)

var binaryRules = []Rule{ruleNoPIE, ruleNoCanary, ruleNoARC, ruleNotStripped, ruleDebugInfo, ruleEncrypted, ruleUnsafeC, ruleWeakRandom, ruleWeakHash, ruleWeakCipher}

// Imported symbols that trip each import-based rule.
var importRules = []struct {
	rule    Rule
	symbols []string
}{
	{ruleUnsafeC, []string{"_strcpy", "_strcat", "_sprintf", "_vsprintf", "_gets"}},
	{ruleWeakRandom, []string{"_rand", "_random", "_srand", "_srandom"}},
	{ruleWeakHash, []string{"_CC_MD5", "_CC_MD5_Init", "_CC_SHA1", "_CC_SHA1_Init"}},
	{ruleWeakCipher, []string{"_CCCrypt", "_CCCryptorCreate", "_CCCryptorCreateWithMode"}},
}

func binaryChecks(app *bundle.App) []scan.Finding {
	b := app.Binary
	var out []scan.Finding

	if !b.PIE {
		out = append(out, ruleNoPIE.finding("Mach-O header flag MH_PIE is not set"))
	}
	if !b.StackCanary {
		out = append(out, ruleNoCanary.finding("No import of ___stack_chk_guard or ___stack_chk_fail"))
	}
	if b.ObjC && !b.ARC {
		out = append(out, ruleNoARC.finding("Objective-C runtime used, no objc_release / objc_storeStrong imports"))
	}
	if !b.Stripped {
		out = append(out, ruleNotStripped.finding("Local symbol table entries present"))
	}
	if b.DebugInfo {
		out = append(out, ruleDebugInfo.finding("__DWARF segment or STABS debug entries present"))
	}
	if b.Encrypted {
		out = append(out, ruleEncrypted.finding("LC_ENCRYPTION_INFO cryptid = 1"))
	}

	imports := map[string]bool{}
	for _, s := range b.Imports {
		imports[s] = true
	}
	for _, ir := range importRules {
		var hit []string
		for _, s := range ir.symbols {
			if imports[s] {
				hit = append(hit, s[1:]+"()") // drop the Mach-O leading underscore
			}
		}
		if len(hit) > 0 {
			sort.Strings(hit)
			out = append(out, ir.rule.finding(hit...))
		}
	}
	return out
}
