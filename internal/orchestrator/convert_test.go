package orchestrator

import (
	"encoding/json"
	"testing"

	"github.com/harshmaur/audr/internal/finding"
)

func TestCategorizeRuleIDDispatch(t *testing.T) {
	cases := []struct {
		ruleID string
		want   string
	}{
		{"claude-hook-shell-rce", "ai-agent"},
		{"codex-trust-home-or-broad", "ai-agent"},
		{"secret-betterleaks-valid", "secrets"},
		{"secret-betterleaks-unverified", "secrets"},
		{"osv-dpkg-openssl", "deps"},
		{"dep-something", "deps"},
		{"ospkg-some-cve", "os-pkg"},
		{"unknown-future-rule", "ai-agent"}, // fallback bucket
	}
	for _, tt := range cases {
		t.Run(tt.ruleID, func(t *testing.T) {
			if got := categorizeRuleID(tt.ruleID); got != tt.want {
				t.Errorf("category(%q) = %q, want %q", tt.ruleID, got, tt.want)
			}
		})
	}
}

func TestFindingToStateFindingShape(t *testing.T) {
	args := finding.Args{
		RuleID:      "rule-x",
		Severity:    finding.SeverityHigh,
		Title:       "title",
		Description: "desc",
		Path:        "/a/b/c.toml",
		Line:        42,
		Match:       "redacted-match",
	}
	f := finding.New(args)

	got, err := findingToStateFinding(f, 7, "ai-agent")
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if got.RuleID != "rule-x" {
		t.Errorf("RuleID = %q, want rule-x", got.RuleID)
	}
	if got.Severity != "high" {
		t.Errorf("Severity = %q, want high (typed Severity must stringify)", got.Severity)
	}
	if got.Category != "ai-agent" {
		t.Errorf("Category = %q, want ai-agent", got.Category)
	}
	if got.Kind != "file" {
		t.Errorf("Kind = %q, want file (all rule findings are file-kind in v1)", got.Kind)
	}
	if got.FirstSeenScan != 7 || got.LastSeenScan != 7 {
		t.Errorf("scan IDs = %d/%d, want 7/7", got.FirstSeenScan, got.LastSeenScan)
	}

	// Locator round-trips through JSON with {path, line}.
	var loc map[string]any
	if err := json.Unmarshal(got.Locator, &loc); err != nil {
		t.Fatalf("locator JSON: %v", err)
	}
	if loc["path"] != "/a/b/c.toml" {
		t.Errorf("locator.path = %v, want /a/b/c.toml", loc["path"])
	}
	// line round-trips as float64 from json.Unmarshal into any.
	if l, ok := loc["line"].(float64); !ok || int(l) != 42 {
		t.Errorf("locator.line = %v (%T), want 42", loc["line"], loc["line"])
	}

	// Fingerprint is non-empty and hex-shaped.
	if len(got.Fingerprint) != 64 {
		t.Errorf("fingerprint length = %d, want 64 (sha256 hex)", len(got.Fingerprint))
	}
}

// TestFindingToStateFindingCarriesProjectFields verifies the bug-fix
// for v6 project columns: findingToStateFinding MUST copy ProjectID,
// ProjectLabel, ProjectClass from the input finding.Finding to the
// output state.Finding. Without this, the classifier output gets
// silently dropped at the orchestrator's persistence boundary and
// the dashboard sees 0 projects despite a successful classification.
func TestFindingToStateFindingCarriesProjectFields(t *testing.T) {
	args := finding.Args{
		RuleID:   "rule-x",
		Severity: finding.SeverityHigh,
		Title:    "t",
		Path:     "/home/u/projects/audr/main.go",
		Line:     1,
	}
	f := finding.New(args)
	// Simulate what triage.FillTriageFields would set.
	f.ProjectID = "/home/u/projects/audr"
	f.ProjectLabel = "audr"
	f.ProjectClass = "code-project"

	got, err := findingToStateFinding(f, 1, "ai-agent")
	if err != nil {
		t.Fatal(err)
	}
	if got.ProjectID != f.ProjectID {
		t.Errorf("ProjectID dropped: got %q, want %q", got.ProjectID, f.ProjectID)
	}
	if got.ProjectLabel != f.ProjectLabel {
		t.Errorf("ProjectLabel dropped: got %q, want %q", got.ProjectLabel, f.ProjectLabel)
	}
	if got.ProjectClass != f.ProjectClass {
		t.Errorf("ProjectClass dropped: got %q, want %q", got.ProjectClass, f.ProjectClass)
	}
}

// TestDepscanFindingToStateCarriesProjectFields covers the same fix
// for the depscan-emitter conversion path.
func TestDepscanFindingToStateCarriesProjectFields(t *testing.T) {
	args := finding.Args{
		RuleID:   "dependency-osv-vulnerability",
		Severity: finding.SeverityHigh,
		Title:    "t",
		Path:     "/home/u/projects/audr/package-lock.json",
		Match:    "npm undici@5.28.0",
		Context:  "advisory=GHSA-xxxx-yyyy fixed=5.28.4",
	}
	f := finding.New(args)
	f.ProjectID = "/home/u/projects/audr"
	f.ProjectLabel = "audr"
	f.ProjectClass = "code-project"

	got, err := depscanFindingToState(f, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got.ProjectID != f.ProjectID || got.ProjectLabel != f.ProjectLabel || got.ProjectClass != f.ProjectClass {
		t.Errorf("dep-package project fields dropped: id=%q label=%q class=%q",
			got.ProjectID, got.ProjectLabel, got.ProjectClass)
	}
}

func TestParseDepscanMatchSplitsCorrectly(t *testing.T) {
	cases := []struct {
		match            string
		wantEco, wantName, wantVer string
		wantOK           bool
	}{
		{"npm lodash@4.17.20", "npm", "lodash", "4.17.20", true},
		{"npm @types/node@20.10.5", "npm", "@types/node", "20.10.5", true},
		{"PyPI requests@2.31.0", "PyPI", "requests", "2.31.0", true},
		{"Go github.com/foo/bar@v1.2.3", "Go", "github.com/foo/bar", "v1.2.3", true},
		{"crates serde@1.0.193", "crates", "serde", "1.0.193", true},
		// Malformed inputs return ok=false (caller falls back).
		{"no-spaces", "", "", "", false},
		{"ecosystem name-no-at", "", "", "", false},
		{"ecosystem @leading-at-only", "", "", "", false},
	}
	for _, tt := range cases {
		t.Run(tt.match, func(t *testing.T) {
			eco, name, ver, ok := parseDepscanMatch(tt.match)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v (eco=%q name=%q ver=%q)", ok, tt.wantOK, eco, name, ver)
			}
			if !tt.wantOK {
				return
			}
			if eco != tt.wantEco || name != tt.wantName || ver != tt.wantVer {
				t.Errorf("got (%q, %q, %q), want (%q, %q, %q)", eco, name, ver, tt.wantEco, tt.wantName, tt.wantVer)
			}
		})
	}
}

func TestParseDepscanContextExtractsAdvisoryAndFixed(t *testing.T) {
	advisory, fixed := parseDepscanContext("advisory=CVE-2020-8203 fixed=4.17.21")
	if advisory != "CVE-2020-8203" {
		t.Errorf("advisory = %q, want CVE-2020-8203", advisory)
	}
	if fixed != "4.17.21" {
		t.Errorf("fixed = %q, want 4.17.21", fixed)
	}

	// Missing fixed is OK.
	advisory, fixed = parseDepscanContext("advisory=GHSA-xxxx")
	if advisory != "GHSA-xxxx" || fixed != "" {
		t.Errorf("got (%q, %q), want (GHSA-xxxx, empty)", advisory, fixed)
	}
}

func TestDepscanFindingToStateProducesDepPackageKind(t *testing.T) {
	f := finding.New(finding.Args{
		RuleID:      "osv-vulnerability",
		Severity:    finding.SeverityHigh,
		Title:       "Vulnerable dependency: lodash",
		Description: "CVE-2020-8203: prototype pollution",
		Path:        "/home/u/code/dashboard-app/package-lock.json",
		Match:       "npm lodash@4.17.20",
		Context:     "advisory=CVE-2020-8203 fixed=4.17.21",
	})
	sf, err := depscanFindingToState(f, 42)
	if err != nil {
		t.Fatal(err)
	}
	if sf.Kind != "dep-package" {
		t.Errorf("kind = %q, want dep-package", sf.Kind)
	}
	if sf.Category != "deps" {
		t.Errorf("category = %q, want deps", sf.Category)
	}
	if sf.MatchRedacted != "CVE-2020-8203" {
		t.Errorf("MatchRedacted = %q, want CVE-2020-8203 (advisory extracted from Context)", sf.MatchRedacted)
	}
	if sf.RuleID != "osv-npm-package" {
		t.Errorf("rule_id = %q, want osv-npm-package (ecosystem dispatch)", sf.RuleID)
	}

	// Locator round-trips with the structured shape.
	var loc map[string]any
	if err := json.Unmarshal(sf.Locator, &loc); err != nil {
		t.Fatal(err)
	}
	if loc["ecosystem"] != "npm" || loc["name"] != "lodash" || loc["version"] != "4.17.20" {
		t.Errorf("locator = %+v, missing fields", loc)
	}
	if loc["manifest_path"] != "/home/u/code/dashboard-app/package-lock.json" {
		t.Errorf("manifest_path = %v, want the file path", loc["manifest_path"])
	}
}

func TestDepscanFindingToStateFallbackOnUnparseableMatch(t *testing.T) {
	// Match doesn't fit "<eco> <name>@<ver>" — converter falls back
	// to file-kind treatment so the finding still surfaces (better
	// than dropping it silently).
	f := finding.New(finding.Args{
		RuleID:   "osv-vulnerability",
		Severity: finding.SeverityMedium,
		Title:    "weird match",
		Path:     "/m.json",
		Match:    "unparseable",
	})
	sf, err := depscanFindingToState(f, 1)
	if err != nil {
		t.Fatal(err)
	}
	if sf.Kind != "file" {
		t.Errorf("kind = %q, want file (fallback)", sf.Kind)
	}
}

func TestRuleIDForDepEcosystemNormalizes(t *testing.T) {
	cases := map[string]string{
		"npm":     "osv-npm-package",
		"NPM":     "osv-npm-package",
		"PyPI":    "osv-pypi-package",
		"Go":      "osv-go-package",
		"Maven":   "osv-maven-package",
		"crates.io": "osv-crates-io-package",
	}
	for in, want := range cases {
		if got := ruleIDForDepEcosystem(in); got != want {
			t.Errorf("ruleIDForDepEcosystem(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFindingToStateFindingFingerprintStableAcrossEquivalentInputs(t *testing.T) {
	// Same rule + same path/line + same match → same fingerprint.
	// This is the contract that lets resolution detection work:
	// re-detecting the same finding next cycle MUST produce the same
	// fingerprint so it doesn't look like a new row.
	mk := func() finding.Finding {
		return finding.New(finding.Args{
			RuleID: "r", Severity: finding.SeverityHigh,
			Path: "/p", Line: 10, Match: "m",
		})
	}
	a, err := findingToStateFinding(mk(), 1, "ai-agent")
	if err != nil {
		t.Fatal(err)
	}
	b, err := findingToStateFinding(mk(), 2, "ai-agent") // different scan ID — irrelevant to fingerprint
	if err != nil {
		t.Fatal(err)
	}
	if a.Fingerprint != b.Fingerprint {
		t.Errorf("fingerprint drift across equivalent inputs: %s vs %s", a.Fingerprint, b.Fingerprint)
	}
}

// TestBetterleaksValidAndUnverifiedShareFingerprint pins the
// resolution-churn fix. When betterleaks's validation status flips
// between scans (validation API rate-limit, transient network
// failure, key briefly revoked then restored), the same secret
// must keep the same fingerprint — otherwise the old row gets
// marked resolved and a new one opens, inflating "Resolved Today"
// with phantom resolutions for a secret that never went away.
func TestBetterleaksValidAndUnverifiedShareFingerprint(t *testing.T) {
	mk := func(ruleID string) finding.Finding {
		return finding.New(finding.Args{
			RuleID: ruleID, Severity: finding.SeverityHigh,
			Path: "/secrets/.env", Line: 1, Match: "rule=openai-api-key secret=[REDACTED]",
		})
	}
	verified, err := findingToStateFinding(mk("secret-betterleaks-valid"), 1, "secrets")
	if err != nil {
		t.Fatal(err)
	}
	unverified, err := findingToStateFinding(mk("secret-betterleaks-unverified"), 1, "secrets")
	if err != nil {
		t.Fatal(err)
	}
	if verified.Fingerprint != unverified.Fingerprint {
		t.Errorf("betterleaks valid/unverified produced different fingerprints — every validation flap will churn the dashboard:\n  valid:      %s\n  unverified: %s", verified.Fingerprint, unverified.Fingerprint)
	}
	// The actual RuleID stored on each row should still differ —
	// only the fingerprint hash collapses.
	if verified.RuleID == unverified.RuleID {
		t.Errorf("RuleID should reflect verification state for display: got %q == %q", verified.RuleID, unverified.RuleID)
	}
}
