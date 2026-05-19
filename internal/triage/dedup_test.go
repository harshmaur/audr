package triage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/harshmaur/audr/internal/classify"
	"github.com/harshmaur/audr/internal/finding"
)

func TestDefaultDedupKey_StableAcrossPaths(t *testing.T) {
	// Two findings of the same rule on different paths with the same
	// match payload MUST produce the same dedup key — that is the
	// whole point of the v1.3 roll-up.
	a := finding.Finding{
		RuleID: "dependency-osv-vulnerability",
		Match:  "picomatch < 2.3.1 (CVE-2024-xxxx)",
		Path:   "/home/alice/projects/foo/package-lock.json",
	}
	b := finding.Finding{
		RuleID: "dependency-osv-vulnerability",
		Match:  "picomatch < 2.3.1 (CVE-2024-xxxx)",
		Path:   "/home/alice/.claude/plugins/cache/vercel/0.42.1/bun.lock",
	}
	if DefaultDedupKey(a) != DefaultDedupKey(b) {
		t.Errorf("same rule + same match across paths must collapse — got %q vs %q",
			DefaultDedupKey(a), DefaultDedupKey(b))
	}
}

func TestDefaultDedupKey_DistinctAcrossRules(t *testing.T) {
	// Different rule IDs must produce different keys even when match
	// strings collide — guarantees cross-rule false-positive collapses
	// are impossible by construction.
	a := finding.Finding{RuleID: "rule-one", Match: "same-payload"}
	b := finding.Finding{RuleID: "rule-two", Match: "same-payload"}
	if DefaultDedupKey(a) == DefaultDedupKey(b) {
		t.Errorf("different rules must NOT collapse: %q == %q",
			DefaultDedupKey(a), DefaultDedupKey(b))
	}
	// Sanity — both keys are prefixed by rule_id.
	if !strings.HasPrefix(DefaultDedupKey(a), "rule-one:") {
		t.Errorf("key lost rule prefix: %q", DefaultDedupKey(a))
	}
	if !strings.HasPrefix(DefaultDedupKey(b), "rule-two:") {
		t.Errorf("key lost rule prefix: %q", DefaultDedupKey(b))
	}
}

func TestDefaultDedupKey_DistinctAcrossMatches(t *testing.T) {
	a := finding.Finding{RuleID: "rx", Match: "picomatch < 2.3.1"}
	b := finding.Finding{RuleID: "rx", Match: "undici < 5.28.4"}
	if DefaultDedupKey(a) == DefaultDedupKey(b) {
		t.Errorf("different matches must NOT collapse: %q == %q",
			DefaultDedupKey(a), DefaultDedupKey(b))
	}
}

func TestDefaultDedupKey_NormalisesWhitespaceAndCase(t *testing.T) {
	a := finding.Finding{RuleID: "rx", Match: "Foo Bar"}
	b := finding.Finding{RuleID: "rx", Match: "  foo bar  "}
	if DefaultDedupKey(a) != DefaultDedupKey(b) {
		t.Errorf("case+whitespace variants must collapse: %q vs %q",
			DefaultDedupKey(a), DefaultDedupKey(b))
	}
}

func TestDefaultDedupKey_FallsBackToTitleWhenMatchEmpty(t *testing.T) {
	// Rules without a redacted match payload (e.g. structural checks)
	// must still get a distinct key per (rule, title).
	a := finding.Finding{RuleID: "structural", Title: "Hook exposes shell"}
	b := finding.Finding{RuleID: "structural", Title: "Permission allowlist too broad"}
	if DefaultDedupKey(a) == DefaultDedupKey(b) {
		t.Errorf("title fallback must distinguish: got identical key %q", DefaultDedupKey(a))
	}
}

func TestFillTriageFields_RulePopulatedFieldsWin(t *testing.T) {
	const home = "/home/alice"
	rulePopulated := finding.Finding{
		RuleID:          "dependency-osv-vulnerability",
		Path:            home + "/.claude/plugins/cache/vercel/0.42.1/bun.lock",
		DedupGroupKey:   "osv:picomatch:2.3.1:CVE-2024-xxxx",
		FixAuthority:    finding.FixAuthorityMaintainer,
		SecondaryNotify: "vercel-pinned-from-rule",
	}
	got := FillTriageFields(rulePopulated, home, nil)
	if got.DedupGroupKey != "osv:picomatch:2.3.1:CVE-2024-xxxx" {
		t.Errorf("rule-supplied DedupGroupKey was overwritten: %q", got.DedupGroupKey)
	}
	if got.FixAuthority != finding.FixAuthorityMaintainer {
		t.Errorf("rule-supplied FixAuthority was overwritten: %q", got.FixAuthority)
	}
	if got.SecondaryNotify != "vercel-pinned-from-rule" {
		t.Errorf("rule-supplied SecondaryNotify was overwritten: %q", got.SecondaryNotify)
	}
}

func TestFillTriageFields_BlanksGetClassified(t *testing.T) {
	const home = "/home/alice"
	f := finding.Finding{
		RuleID: "dependency-osv-vulnerability",
		Match:  "picomatch < 2.3.1",
		Path:   home + "/.claude/plugins/cache/vercel/0.42.1/bun.lock",
	}
	got := FillTriageFields(f, home, nil)
	if got.DedupGroupKey == "" {
		t.Error("blank DedupGroupKey should be filled with default")
	}
	if got.FixAuthority != finding.FixAuthorityMaintainer {
		t.Errorf("blank FixAuthority should be classified MAINTAINER, got %q", got.FixAuthority)
	}
	if got.SecondaryNotify != "vercel" {
		t.Errorf("SecondaryNotify should be 'vercel' from path-class, got %q", got.SecondaryNotify)
	}
}

// TestFillTriageFields_PopulatesProjectFieldsFromClassifier covers
// the v6 project-metadata wiring: when a Classifier is supplied,
// FillTriageFields populates Finding.ProjectID + ProjectLabel +
// ProjectClass.
func TestFillTriageFields_PopulatesProjectFieldsFromClassifier(t *testing.T) {
	home := t.TempDir()

	// Real code-project (go.mod) so the classifier returns concrete
	// info, not the fallback.
	projDir := filepath.Join(home, "projects", "audr")
	if err := os.MkdirAll(filepath.Join(projDir, "cmd", "audr"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projDir, "go.mod"), []byte("module audr"), 0o644); err != nil {
		t.Fatal(err)
	}
	findingPath := filepath.Join(projDir, "cmd", "audr", "main.go")
	if err := os.WriteFile(findingPath, []byte("package main"), 0o644); err != nil {
		t.Fatal(err)
	}

	pc, err := classify.NewClassifier(home)
	if err != nil {
		t.Fatal(err)
	}

	f := finding.Finding{
		RuleID: "secret-anthropic-key",
		Match:  "ant-...",
		Path:   findingPath,
	}
	got := FillTriageFields(f, home, pc)

	if got.ProjectClass != "code-project" {
		t.Errorf("expected ProjectClass=code-project, got %q", got.ProjectClass)
	}
	if got.ProjectLabel != "audr" {
		t.Errorf("expected ProjectLabel=audr, got %q", got.ProjectLabel)
	}
	if got.ProjectID == "" {
		t.Error("expected non-empty ProjectID")
	}
}

// TestFillTriageFields_NilClassifierLeavesProjectFieldsEmpty documents
// the CLI-scan fallback: no classifier → project fields stay empty.
// Dashboard renders these as the "loose" fallback. Also a regression
// check that the new flow didn't break the old DedupGroupKey filling.
func TestFillTriageFields_NilClassifierLeavesProjectFieldsEmpty(t *testing.T) {
	const home = "/home/alice"
	f := finding.Finding{
		RuleID: "dependency-osv-vulnerability",
		Match:  "picomatch < 2.3.1",
		Path:   home + "/projects/audr/package-lock.json",
	}
	got := FillTriageFields(f, home, nil)
	if got.ProjectID != "" || got.ProjectLabel != "" || got.ProjectClass != "" {
		t.Errorf("nil classifier should leave project fields empty; got id=%q label=%q class=%q",
			got.ProjectID, got.ProjectLabel, got.ProjectClass)
	}
	if got.DedupGroupKey == "" {
		t.Error("DedupGroupKey should still be filled when classifier is nil")
	}
}

// TestFillTriageFields_RulePopulatedProjectFieldsWin: rules that
// pre-populate ProjectID etc. should win over the classifier.
func TestFillTriageFields_RulePopulatedProjectFieldsWin(t *testing.T) {
	home := t.TempDir()
	pc, err := classify.NewClassifier(home)
	if err != nil {
		t.Fatal(err)
	}
	f := finding.Finding{
		RuleID:       "secret-anthropic-key",
		Path:         home + "/projects/audr/main.go",
		ProjectID:    "pre-populated-id",
		ProjectLabel: "pre-populated-label",
		ProjectClass: "code-project",
	}
	got := FillTriageFields(f, home, pc)
	if got.ProjectID != "pre-populated-id" {
		t.Errorf("rule-supplied ProjectID was overwritten: %q", got.ProjectID)
	}
	if got.ProjectLabel != "pre-populated-label" {
		t.Errorf("rule-supplied ProjectLabel was overwritten: %q", got.ProjectLabel)
	}
}

func TestFillTriageFields_UserProjectFallthrough(t *testing.T) {
	const home = "/home/alice"
	f := finding.Finding{
		RuleID: "dependency-osv-vulnerability",
		Match:  "picomatch < 2.3.1",
		Path:   home + "/projects/audr/package-lock.json",
	}
	got := FillTriageFields(f, home, nil)
	if got.FixAuthority != finding.FixAuthorityYou {
		t.Errorf("user project should fall through to YOU, got %q", got.FixAuthority)
	}
	if got.SecondaryNotify != "" {
		t.Errorf("user project should not carry SecondaryNotify, got %q", got.SecondaryNotify)
	}
}
