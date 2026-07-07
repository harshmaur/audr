package builtin

import (
	"testing"

	"github.com/harshmaur/audr/internal/parse"
)

func TestDeepTutorMCPToolGrantBypass_FlagsVulnerableRequirements(t *testing.T) {
	doc := parse.Parse("requirements.txt", []byte("deeptutor==1.4.9\n"))
	findings := (deeptutorMCPToolGrantBypass{}).Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].RuleID != "deeptutor-mcp-tool-grant-bypass" {
		t.Fatalf("rule id = %q", findings[0].RuleID)
	}
	if findings[0].Line != 1 {
		t.Fatalf("line = %d, want 1", findings[0].Line)
	}
}

func TestDeepTutorMCPToolGrantBypass_FlagsVulnerablePyproject(t *testing.T) {
	doc := parse.Parse("pyproject.toml", []byte(`[project]
dependencies = [
  "deeptutor>=1.4.0,<1.4.10",
]
`))
	findings := (deeptutorMCPToolGrantBypass{}).Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
}

func TestDeepTutorMCPToolGrantBypass_AllowsFixedVersion(t *testing.T) {
	doc := parse.Parse("requirements.txt", []byte("deeptutor==1.4.10\n"))
	findings := (deeptutorMCPToolGrantBypass{}).Apply(doc)
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0", len(findings))
	}
}
