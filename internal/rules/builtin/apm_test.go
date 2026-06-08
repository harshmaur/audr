package builtin

import (
	"testing"

	"github.com/harshmaur/audr/internal/parse"
)

func TestAPMPluginManifestFormat(t *testing.T) {
	if got := parse.DetectFormat("/repo/plugin.json"); got != parse.FormatAPMPluginManifest {
		t.Fatalf("DetectFormat(plugin.json) = %q, want %q", got, parse.FormatAPMPluginManifest)
	}
}

func TestMicrosoftAPMPluginTraversalDetectsEscapingComponentRefs(t *testing.T) {
	doc := parse.Parse("/repo/plugin.json", []byte(`{
		"agents": ["agents/main.md", "../secrets/agent.md"],
		"skills": [{"path": "/etc/passwd"}],
		"commands": {"build": "C:/Users/alice/.ssh/id_rsa"},
		"hooks": ["..\\..\\Windows\\win.ini"]
	}`))

	findings := microsoftAPMPluginComponentTraversal{}.Apply(doc)
	if len(findings) != 4 {
		t.Fatalf("findings = %d, want 4: %#v", len(findings), findings)
	}
	for _, f := range findings {
		if f.RuleID != "microsoft-apm-plugin-component-traversal" {
			t.Fatalf("RuleID = %q", f.RuleID)
		}
		if f.Line == 0 {
			t.Fatalf("expected line number in finding: %#v", f)
		}
	}
}

func TestMicrosoftAPMPluginTraversalIgnoresPluginLocalRefs(t *testing.T) {
	doc := parse.Parse("/repo/plugin.json", []byte(`{
		"agents": ["agents/main.md"],
		"skills": [{"path": "skills/review.md"}],
		"commands": {"build": "commands/build.sh"},
		"hooks": ["hooks/preinstall.js"]
	}`))

	rule := microsoftAPMPluginComponentTraversal{}
	if findings := rule.Apply(doc); len(findings) != 0 {
		t.Fatalf("findings = %#v, want none", findings)
	}
}
