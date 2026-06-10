package builtin

import (
	"testing"

	"github.com/harshmaur/audr/internal/parse"
)

func TestLibreChatMCPEnvSecretLeak_FlagsVulnerablePackage(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{"dependencies":{"librechat":"0.8.3"}}`))
	findings := (libreChatMCPEnvSecretLeak{}).Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if findings[0].RuleID != "librechat-mcp-env-secret-leak" {
		t.Fatalf("rule id = %q", findings[0].RuleID)
	}
}

func TestLibreChatMCPEnvSecretLeak_FlagsScopedPackageRange(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{"devDependencies":{"@librechat/api":"^0.8.3"}}`))
	findings := (libreChatMCPEnvSecretLeak{}).Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
}

func TestLibreChatMCPEnvSecretLeak_AllowsFixedVersion(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{"dependencies":{"librechat":"0.8.4"}}`))
	findings := (libreChatMCPEnvSecretLeak{}).Apply(doc)
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(findings))
	}
}

func TestLibreChatMCPEnvSecretLeak_IgnoresUnrelatedPackage(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{"dependencies":{"@librechat/client":"0.8.3"}}`))
	findings := (libreChatMCPEnvSecretLeak{}).Apply(doc)
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(findings))
	}
}
