package builtin

import (
	"testing"

	"github.com/harshmaur/audr/internal/parse"
)

func TestDeepSeekMCPSessionIDHijack_FlagsVulnerablePackage(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{"name":"@arikusi/deepseek-mcp-server","version":"1.4.2"}`))
	findings := (deepseekMCPSessionIDHijack{}).Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].RuleID != "deepseek-mcp-session-id-hijack" {
		t.Fatalf("rule id = %q", findings[0].RuleID)
	}
}

func TestDeepSeekMCPSessionIDHijack_FlagsVulnerableDependency(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{"dependencies":{"@arikusi/deepseek-mcp-server":"^1.6.9"}}`))
	if findings := (deepseekMCPSessionIDHijack{}).Apply(doc); len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
}

func TestDeepSeekMCPSessionIDHijack_AllowsFixedVersion(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{"dependencies":{"@arikusi/deepseek-mcp-server":"1.7.0"}}`))
	if findings := (deepseekMCPSessionIDHijack{}).Apply(doc); len(findings) != 0 {
		t.Fatalf("got %d findings, want 0", len(findings))
	}
}

func TestDeepSeekMCPSessionIDHijack_AllowsPreIntroductionVersion(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{"dependencies":{"@arikusi/deepseek-mcp-server":"1.4.1"}}`))
	if findings := (deepseekMCPSessionIDHijack{}).Apply(doc); len(findings) != 0 {
		t.Fatalf("got %d findings, want 0", len(findings))
	}
}
