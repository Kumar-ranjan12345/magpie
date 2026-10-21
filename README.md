# 🐦 Magpie

**Find the shiny things you left in your iOS app.**

Magpie is a fast, single-binary security scanner for iOS apps. Point it at an `.ipa` or `.app` and in under a second it tells you what an attacker would find: leaked API keys, disabled App Transport Security, debuggable builds, weak crypto, staging URLs, private keys in the bundle and more. Every finding comes with a plain-English explanation, the evidence, and how to fix it, mapped to [OWASP MASVS](https://mas.owasp.org/MASVS/).

```
$ magpie scan MyApp.ipa

🐦 Magpie — iOS app security scan

  App          MyApp
  Bundle ID    com.example.myapp
  Minimum iOS  14.0

  Grade F  score 0/100   1 critical  2 high  5 medium  10 low  3 info

  CRITICAL MP-STG-002  Private key or keystore file bundled in the app
           Storage · MASVS-CRYPTO-2
           Files such as .p12, .pfx, .pem and .key usually hold private keys. Anyone who
           downloads the app can extract them and impersonate your client or server.
           › client.p12
           Fix: Remove the file from the target and rotate the key. ...

  HIGH     MP-NET-001  App Transport Security disabled for all connections
  ...
```

## Why Magpie

- **iOS-first.** Built for Mach-O, Info.plist, entitlements and code signatures, not an Android tool with iOS bolted on.
- **One binary, no setup.** No Python, no Docker, no server. Runs on macOS, Linux and Windows.
- **Made for developers.** Each finding says why it matters and exactly what to change in Xcode.
- **CI-ready.** JSON and SARIF output and `-fail-on` exit codes so a pipeline can block a risky build, plus a self-contained HTML report to share with your team.

## Install

```sh
go install github.com/Kumar-ranjan12345/magpie/cmd/magpie@latest
```

## Usage

### Drag and drop

```sh
magpie serve
```

Opens a page in your browser at `http://127.0.0.1:8077`. Drop an `.ipa` (or a zipped `.app`) on it and the report appears right there, with a button to save it. Everything stays on your computer, and uploaded apps are deleted as soon as the scan finishes.

### Command line

```sh
magpie scan MyApp.ipa                   # coloured report in the terminal
magpie scan MyApp.app -format json      # machine-readable report
magpie scan MyApp.ipa -format html -o report.html   # shareable report page
magpie scan MyApp.ipa -format sarif -o magpie.sarif # GitHub code scanning / CI
magpie scan MyApp.ipa -fail-on high     # exit 1 if anything high or critical is found
magpie rules                            # list every check
```

Exit codes: `0` ok · `1` findings at or above `-fail-on` · `2` error.

## What it checks

| Area | Examples |
|---|---|
| **Binary hardening** | PIE, stack canaries, ARC, stripped symbols, embedded debug info |
| **Secrets** | AWS, Stripe, GitHub, Slack, OpenAI, Anthropic, Twilio, SendGrid keys, PEM private keys, JWTs, Google API keys |
| **Network** | ATS disabled globally or for web content, insecure HTTP and old TLS exceptions, cleartext URLs, bundled pinning certificates |
| **Entitlements** | `get-task-allow` (debuggable), development push, wildcard keychain groups |
| **Crypto** | MD5 / SHA-1, `rand()`, legacy `CCCrypt` |
| **Storage** | Documents exposed via Files, bundled keystores, databases and `.env` files |
| **Build hygiene** | localhost / staging URLs, source files in the bundle, old deployment targets |
| **Resilience** | Jailbreak detection, anti-debugging (`ptrace`), Frida / Substrate hooking detection, App Attest / DeviceCheck, known protection SDKs (IOSSecuritySuite, freeRASP, iXGuard…) |
| **Supply chain & privacy** | Embedded framework inventory with versions, analytics / ad SDKs, outdated OpenSSL |
| **Platform** | Custom URL schemes, background modes |

Run `magpie rules` for the full list with IDs and severities.

## Grading

Each finding deducts points from 100 (critical 30, high 15, medium 8, low 3, info 0), which maps to a grade from A to F. A critical finding caps the grade at D and a high finding at C, so a single leaked key can't hide behind an otherwise clean app.

## Limitations

- **App Store downloads are encrypted.** IPAs pulled from the App Store have FairPlay-encrypted code, so binary string checks (secrets, URLs) can't read it. Magpie detects this and still scans Info.plist, entitlements and bundled files. For a full scan use an Xcode archive export of your own app.
- **Static analysis only.** Magpie reads the app; it doesn't run it. It can tell you CCCrypt is used, not whether it's used in ECB mode.
- **Protections are detected, not rated.** Magpie can see that an app checks for jailbreaks or Frida, not how easily those checks are bypassed. Obfuscated or commercial protections may not be visible at all.
- **Scan only apps you own or are authorised to test.**

## Development

```sh
go test ./...
```

`testdata/VulnerableApp.app` is a deliberately insecure fixture app that trips most rules, and `testdata/ProtectedApp.app` has jailbreak, anti-debugging, hooking and App Attest checks. Their binaries are built from `testdata/src`:

```sh
cd testdata/src
xcrun clang -arch arm64 -isysroot "$(xcrun --sdk iphoneos --show-sdk-path)" \
  -miphoneos-version-min=14.0 -fno-stack-protector -O0 -g vulnerable.c -o ../VulnerableApp.app/VulnerableApp
codesign -f -s - --entitlements entitlements.plist ../VulnerableApp.app/VulnerableApp

xcrun clang -arch arm64 -isysroot "$(xcrun --sdk iphoneos --show-sdk-path)" -miphoneos-version-min=16.0 \
  -fobjc-arc -Os protected.m -framework Foundation -framework DeviceCheck -o ../ProtectedApp.app/ProtectedApp
strip -x ../ProtectedApp.app/ProtectedApp && codesign -f -s - ../ProtectedApp.app/ProtectedApp
```

## License

MIT
