package builtin

import (
	"testing"

	"github.com/harshmaur/audr/internal/parse"
)

func TestLumiverseMCPArgsRCE_FlagsVulnerablePackage(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{
  "name": "lumiverse-backend",
  "version": "0.9.6"
}`))
	findings := (lumiverseMCPArgsRCE{}).Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].RuleID != "lumiverse-mcp-args-rce" {
		t.Fatalf("rule id = %q", findings[0].RuleID)
	}
}

func TestLumiverseMCPArgsRCE_FlagsVulnerableDependency(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{
  "dependencies": {
    "lumiverse-backend": "^0.9.6"
  }
}`))
	findings := (lumiverseMCPArgsRCE{}).Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
}

func TestLumiverseMCPArgsRCE_AllowsFixedVersion(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{
  "dependencies": {
    "lumiverse-backend": "0.9.7"
  }
}`))
	findings := (lumiverseMCPArgsRCE{}).Apply(doc)
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0", len(findings))
	}
}
