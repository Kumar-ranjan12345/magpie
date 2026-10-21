package checks

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Kumar-ranjan12345/magpie/internal/binary"
	"github.com/Kumar-ranjan12345/magpie/internal/bundle"
	"github.com/Kumar-ranjan12345/magpie/internal/scan"
)

const resilienceNote = " Magpie finds signs of these checks in the binary; it cannot tell how hard they are to bypass, and obfuscated or commercial protections may not be visible."

var (
	ruleNoJailbreak = Rule{
		ID: "MP-RES-001", Title: "No jailbreak detection found", Severity: scan.Low,
		Category: "Resilience", MASVS: "MASVS-RESILIENCE-1",
		Description: "No known jailbreak checks were found. On a jailbroken device other code can read the app's Keychain items, files and memory. This matters most for banking, identity, health and payment apps." + resilienceNote,
		Remediation: "Add layered jailbreak checks (suspicious files and URL schemes, sandbox write tests, injected libraries), for example with IOSSecuritySuite, and decide on the server what a flagged device may do. Combine with App Attest.",
	}
	ruleNoAntiDebug = Rule{
		ID: "MP-RES-002", Title: "No anti-debugging found", Severity: scan.Low,
		Category: "Resilience", MASVS: "MASVS-RESILIENCE-4",
		Description: "No ptrace(PT_DENY_ATTACH) or debugger checks were found, so an attacker can attach a debugger to a release build to inspect memory and change behaviour." + resilienceNote,
		Remediation: "Detect an attached debugger (sysctl with KERN_PROC_PID and the P_TRACED flag) and deny attaching in release builds. Run the checks more than once, not only at launch.",
	}
	ruleNoHookDetection = Rule{
		ID: "MP-RES-003", Title: "No hooking framework detection found", Severity: scan.Low,
		Category: "Resilience", MASVS: "MASVS-RESILIENCE-4",
		Description: "No checks for Frida, Substrate or similar instrumentation were found. These tools are the standard way to bypass jailbreak detection, certificate pinning and client-side checks." + resilienceNote,
		Remediation: "Scan loaded libraries (_dyld_image_count / _dyld_get_image_name) for frida, FridaGadget, MobileSubstrate, libhooker and ellekit, and check for the Frida server.",
	}
	ruleNoAttest = Rule{
		ID: "MP-RES-004", Title: "App Attest / DeviceCheck not used", Severity: scan.Info,
		Category: "Resilience", MASVS: "MASVS-RESILIENCE-2",
		Description: "The app does not use Apple's App Attest or DeviceCheck. Client-side checks can always be patched out; App Attest lets your server verify that a request really comes from your unmodified app on a genuine Apple device.",
		Remediation: "Use DCAppAttestService to attest a key at first launch and assert sensitive requests, and verify the attestation on your server.",
	}
	ruleProtections = Rule{
		ID: "MP-RES-005", Title: "Runtime protections detected", Severity: scan.Info,
		Category: "Resilience", MASVS: "MASVS-RESILIENCE-1",
		Description: "Signs of these protections were found." + resilienceNote,
		Remediation: "Verify they hold up on a jailbroken test device with Frida and bypass tweaks (for example Shadow), and make sure the server, not only the app, reacts to a compromised device.",
	}
)

var resilienceRules = []Rule{ruleNoJailbreak, ruleNoAntiDebug, ruleNoHookDetection, ruleNoAttest, ruleProtections}

// Strings that jailbreak checks look for. Most are longer than 15 bytes, so even
// Swift stores them as readable text rather than packing them into instructions.
var jailbreakIndicators = []string{
	"/Applications/Cydia.app", "/Applications/Sileo.app", "/Applications/Zebra.app",
	"/Applications/blackra1n.app", "/Applications/FakeCarrier.app", "/Applications/Icy.app",
	"/Applications/IntelliScreen.app", "/Applications/SBSettings.app", "/Applications/RockApp.app",
	"/Library/MobileSubstrate/MobileSubstrate.dylib", "/Library/MobileSubstrate/DynamicLibraries",
	"/Library/PreferenceLoader", "/usr/libexec/cydia", "/usr/libexec/sftp-server", "/usr/sbin/sshd",
	"/usr/bin/sshd", "/private/var/lib/apt", "/private/var/lib/cydia", "/private/var/stash",
	"/private/var/mobile/Library/SBSettings", "/var/cache/apt", "/var/lib/cydia", "/etc/apt/sources.list",
	"/private/jailbreak.txt", "/.bootstrapped_electra", "/.installed_unc0ver", "/.installed_dopamine",
	"/.bootstrapped", "/var/jb", "/var/binpack", "/usr/lib/libjailbreak.dylib", "/jb/lzma",
	"/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist", "/etc/ssh/sshd_config",
	"cydia://package", "sileo://package", "zbra://packages", "undecimus://", "filza://",
	"checkra1n", "palera1n", "unc0ver",
}

// Lower-cased substrings that point at hooking or instrumentation detection.
var hookIndicators = []string{
	// Not a bare "frida": that also matches "Friday".
	"fridagadget", "frida-server", "frida-agent", "frida-gadget", "libfrida", "re.frida", "frida_",
	"gum-js-loop", "mobilesubstrate", "substrateloader",
	"libcycript", "cynject", "sslkillswitch", "libsubstitute", "libhooker", "ellekit", "substrateinserter",
}

// Third-party protection SDKs, matched case-insensitively against strings and framework names.
var protectionSDKs = map[string]string{
	"iossecuritysuite":      "IOSSecuritySuite",
	"dttjailbreakdetection": "DTTJailbreakDetection",
	"talsec":                "Talsec freeRASP",
	"freerasp":              "Talsec freeRASP",
	"ixguard":               "Guardsquare iXGuard",
	"appdome":               "Appdome",
	"promon":                "Promon SHIELD",
	"zimperium":             "Zimperium zDefend",
	"jailmonkey":            "JailMonkey",
}

// corpus is everything the resilience checks search: imports and strings from
// the main executable and every embedded framework.
type corpus struct {
	imports map[string]bool
	strs    []string
	lower   []string
	names   []string // framework names, lower-cased
}

func buildCorpus(app *bundle.App) corpus {
	c := corpus{imports: map[string]bool{}}
	addBinary := func(b *binary.Info) {
		if b == nil {
			return
		}
		for _, s := range b.Imports {
			c.imports[s] = true
		}
		if !b.Encrypted {
			c.strs = append(c.strs, b.Strings(6)...)
		}
	}
	addBinary(app.Binary)
	for _, fw := range app.Frameworks {
		addBinary(fw.Binary)
		c.names = append(c.names, strings.ToLower(fw.Name))
	}
	c.lower = make([]string, len(c.strs))
	for i, s := range c.strs {
		c.lower[i] = strings.ToLower(s)
	}
	return c
}

// containsAny returns the needles found in the corpus strings, in needle order.
func (c corpus) containsAny(needles []string, lower bool) []string {
	hay := c.strs
	if lower {
		hay = c.lower
	}
	var found []string
	for _, n := range needles {
		for _, s := range hay {
			if strings.Contains(s, n) {
				found = append(found, n)
				break
			}
		}
	}
	return found
}

func (c corpus) hasImport(names ...string) []string {
	var found []string
	for _, n := range names {
		if c.imports[n] {
			found = append(found, strings.TrimPrefix(n, "_")+"()")
		}
	}
	return found
}

func resilienceChecks(app *bundle.App) []scan.Finding {
	c := buildCorpus(app)
	// An encrypted main binary hides its strings, so "not found" would be a guess.
	canJudge := !app.Binary.Encrypted

	var present []string
	var out []scan.Finding

	// Protection SDKs, by framework name or by strings linked in statically.
	sdks := map[string]bool{}
	for key, label := range protectionSDKs {
		for _, n := range c.names {
			if strings.Contains(n, key) {
				sdks[label] = true
			}
		}
	}
	keys := make([]string, 0, len(protectionSDKs))
	for k := range protectionSDKs {
		keys = append(keys, k)
	}
	for _, k := range c.containsAny(keys, true) {
		sdks[protectionSDKs[k]] = true
	}
	var sdkNames []string
	for s := range sdks {
		sdkNames = append(sdkNames, s)
	}
	sort.Strings(sdkNames)
	if len(sdkNames) > 0 {
		present = append(present, "Protection SDK: "+strings.Join(sdkNames, ", "))
	}

	jb := c.containsAny(jailbreakIndicators, false)
	// One stray path can come from a library; two or more means deliberate checks.
	if len(jb) >= 2 || (len(jb) >= 1 && len(sdkNames) > 0) {
		present = append(present, fmt.Sprintf("Jailbreak detection: %d indicators (%s)", len(jb), sample(jb, 4)))
	} else if canJudge && len(sdkNames) == 0 {
		out = append(out, ruleNoJailbreak.finding())
	}

	antiDebug := c.hasImport("_ptrace")
	if c.imports["_dlsym"] && len(c.containsAny([]string{"ptrace"}, false)) > 0 {
		antiDebug = append(antiDebug, "ptrace via dlsym()")
	}
	// sysctl(KERN_PROC_PID) + P_TRACED is the usual Swift debugger check. sysctl has
	// other uses too, so it is reported as likely rather than certain.
	if c.imports["_sysctl"] {
		antiDebug = append(antiDebug, "sysctl() (likely a P_TRACED debugger check)")
	}
	if len(antiDebug) > 0 {
		present = append(present, "Anti-debugging: "+strings.Join(antiDebug, ", "))
	} else if canJudge && len(sdkNames) == 0 {
		out = append(out, ruleNoAntiDebug.finding("No ptrace, dlsym(\"ptrace\") or sysctl usage"))
	}

	hooks := c.containsAny(hookIndicators, true)
	if len(hooks) > 0 {
		ev := "Hooking detection: " + sample(hooks, 4)
		if dyld := c.hasImport("__dyld_image_count", "__dyld_get_image_name"); len(dyld) == 2 {
			ev += "; scans loaded libraries"
		}
		present = append(present, ev)
	} else if canJudge && len(sdkNames) == 0 {
		out = append(out, ruleNoHookDetection.finding())
	}

	attest := c.hasImport("_OBJC_CLASS_$_DCAppAttestService")
	device := c.hasImport("_OBJC_CLASS_$_DCDevice")
	switch {
	case len(attest) > 0:
		present = append(present, "Apple App Attest (DCAppAttestService)")
	case len(device) > 0:
		present = append(present, "Apple DeviceCheck (DCDevice)")
	default:
		out = append(out, ruleNoAttest.finding("No DCAppAttestService or DCDevice class reference"))
	}

	if integ := c.containsAny([]string{"embedded.mobileprovision", "SignerIdentity"}, false); len(integ) > 0 {
		// Weak signal: analytics SDKs read the profile too, to tell debug from release.
		present = append(present, "Possible integrity checks: references "+strings.Join(integ, ", "))
	}

	if len(present) > 0 {
		out = append(out, ruleProtections.finding(present...))
	}
	return out
}

func sample(items []string, n int) string {
	if len(items) <= n {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:n], ", ") + ", …"
}
