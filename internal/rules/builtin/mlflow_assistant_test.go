package builtin

import (
	"testing"

	"github.com/harshmaur/audr/internal/parse"
)

func TestMLflowAssistantOriginBypass_FlagsVulnerableRequirements(t *testing.T) {
	doc := parse.Parse("requirements.txt", []byte("mlflow==3.9.0\n"))
	findings := (mlflowAssistantOriginBypass{}).Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].RuleID != "mlflow-assistant-origin-bypass" {
		t.Fatalf("rule id = %q", findings[0].RuleID)
	}
	if findings[0].Line != 1 {
		t.Fatalf("line = %d, want 1", findings[0].Line)
	}
}

func TestMLflowAssistantOriginBypass_FlagsVulnerablePyproject(t *testing.T) {
	doc := parse.Parse("pyproject.toml", []byte(`[project]
dependencies = [
  "mlflow>=3.9.0,<3.10.0",
]
`))
	findings := (mlflowAssistantOriginBypass{}).Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
}

func TestMLflowAssistantOriginBypass_AllowsBeforeAssistantFeature(t *testing.T) {
	doc := parse.Parse("requirements.txt", []byte("mlflow==3.8.1\n"))
	findings := (mlflowAssistantOriginBypass{}).Apply(doc)
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0", len(findings))
	}
}

func TestMLflowAssistantOriginBypass_AllowsFixedVersion(t *testing.T) {
	doc := parse.Parse("requirements.txt", []byte("mlflow==3.10.0\n"))
	findings := (mlflowAssistantOriginBypass{}).Apply(doc)
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0", len(findings))
	}
}
