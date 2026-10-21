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
	ruleSDKInventory = Rule{
		ID: "MP-SDK-001", Title: "Embedded third-party frameworks", Severity: scan.Info,
		Category: "Supply chain", MASVS: "MASVS-CODE-3",
		Description: "These frameworks ship inside the app and run with its permissions. Statically linked libraries (most Swift packages) are not listed because they become part of the main executable.",
		Remediation: "Keep dependencies current, remove unused ones, and check each SDK's data collection against your privacy manifest.",
	}
	ruleOldOpenSSL = Rule{
		ID: "MP-SDK-002", Title: "Outdated OpenSSL framework", Severity: scan.High,
		Category: "Supply chain", MASVS: "MASVS-CODE-3",
		Description: "OpenSSL 1.x is end of life and no longer receives public security fixes.",
		Remediation: "Upgrade to a supported OpenSSL 3.x build, or drop OpenSSL and use Apple's Security / CryptoKit APIs.",
	}
	ruleTrackingSDK = Rule{
		ID: "MP-PRV-002", Title: "Analytics or advertising SDKs embedded", Severity: scan.Info,
		Category: "Privacy", MASVS: "MASVS-PRIVACY-1",
		Description: "These SDKs collect usage or device data. Apple requires them to be declared in the app's privacy manifest and App Store privacy labels, and some need App Tracking Transparency consent.",
		Remediation: "Confirm each SDK's data types are in PrivacyInfo.xcprivacy and your App Store privacy details, and disable data collection you don't need.",
	}
)

var sdkRules = []Rule{ruleSDKInventory, ruleOldOpenSSL, ruleTrackingSDK}

// Lower-cased framework name prefixes of SDKs that collect analytics or ad data.
var trackingSDKs = []string{
	"mixpanel", "amplitude", "segment", "appsflyer", "adjust", "branch", "fbsdk", "facebook",
	"firebaseanalytics", "googleappmeasurement", "googlemobileads", "clevertap", "moengage",
	"braze", "appboy", "onesignal", "flurry", "kochava", "singular", "applovin", "unityads",
	"ironsource", "chartboost", "webengage", "netcore", "smartech",
}

func sdkChecks(app *bundle.App) []scan.Finding {
	if len(app.Frameworks) == 0 {
		return nil
	}
	var inventory, tracking, openssl []string
	for _, fw := range app.Frameworks {
		label := fw.Name
		if fw.Version != "" {
			label += " " + fw.Version
		}
		inventory = append(inventory, label)

		lower := strings.ToLower(fw.Name)
		for _, t := range trackingSDKs {
			if strings.HasPrefix(lower, t) {
				tracking = append(tracking, label)
				break
			}
		}
		if (lower == "openssl" || lower == "openssl-universal") && majorVersion(fw.Version) == 1 {
			openssl = append(openssl, label)
		}
	}
	sort.Strings(inventory)
	inventoryFinding := ruleSDKInventory.finding()
	// The inventory is the point of this finding, so it is not truncated.
	inventoryFinding.Evidence = append([]string{fmt.Sprintf("%d frameworks", len(inventory))}, inventory...)

	out := []scan.Finding{inventoryFinding}
	if len(tracking) > 0 {
		out = append(out, ruleTrackingSDK.finding(tracking...))
	}
	if len(openssl) > 0 {
		out = append(out, ruleOldOpenSSL.finding(openssl...))
	}
	return out
}

func majorVersion(v string) int {
	n, err := strconv.Atoi(strings.SplitN(v, ".", 2)[0])
	if err != nil {
		return -1
	}
	return n
}
