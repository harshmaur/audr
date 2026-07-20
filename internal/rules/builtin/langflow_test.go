package builtin

import (
	"testing"

	"github.com/harshmaur/audr/internal/parse"
)

func TestLangflowToolGuardCodeInjection_FlagsVulnerableRequirements(t *testing.T) {
	doc := parse.Parse("requirements.txt", []byte("langflow==1.10.0\n"))
	findings := (langflowToolGuardCodeInjection{}).Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].RuleID != "langflow-toolguard-code-injection" {
		t.Fatalf("rule id = %q", findings[0].RuleID)
	}
	if findings[0].Line != 1 {
		t.Fatalf("line = %d, want 1", findings[0].Line)
	}
}

func TestLangflowToolGuardCodeInjection_FlagsVulnerablePyprojectRange(t *testing.T) {
	doc := parse.Parse("pyproject.toml", []byte(`[project]
dependencies = [
  "langflow>=1.0.0,<=1.10.0",
]
`))
	findings := (langflowToolGuardCodeInjection{}).Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
}

func TestLangflowToolGuardCodeInjection_FlagsSpacedVulnerableRange(t *testing.T) {
	doc := parse.Parse("requirements.txt", []byte("langflow>=1.0.0, <1.10.1\n"))
	if findings := (langflowToolGuardCodeInjection{}).Apply(doc); len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
}

func TestLangflowToolGuardCodeInjection_FlagsCompatibleReleaseRange(t *testing.T) {
	doc := parse.Parse("requirements.txt", []byte("langflow~=1.10.0\n"))
	if findings := (langflowToolGuardCodeInjection{}).Apply(doc); len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
}

func TestLangflowToolGuardCodeInjection_AllowsCompatibleRangeBelowAffectedVersions(t *testing.T) {
	doc := parse.Parse("requirements.txt", []byte("langflow~=0.6.0\n"))
	if findings := (langflowToolGuardCodeInjection{}).Apply(doc); len(findings) != 0 {
		t.Fatalf("got %d findings, want 0", len(findings))
	}
}

func TestLangflowToolGuardCodeInjection_FlagsLowerAffectedBoundary(t *testing.T) {
	doc := parse.Parse("requirements.txt", []byte("langflow==1.0.0\n"))
	if findings := (langflowToolGuardCodeInjection{}).Apply(doc); len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
}

func TestLangflowToolGuardCodeInjection_FlagsOverlappingUpperBound(t *testing.T) {
	doc := parse.Parse("requirements.txt", []byte("langflow<1.10.1\n"))
	if findings := (langflowToolGuardCodeInjection{}).Apply(doc); len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
}

func TestLangflowToolGuardCodeInjection_AllowsRangeBelowAffectedVersions(t *testing.T) {
	doc := parse.Parse("requirements.txt", []byte("langflow<1.0.0\n"))
	if findings := (langflowToolGuardCodeInjection{}).Apply(doc); len(findings) != 0 {
		t.Fatalf("got %d findings, want 0", len(findings))
	}
}

func TestLangflowToolGuardCodeInjection_DoesNotTreatNPMNameAsPyPI(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{"dependencies":{"langflow":"1.10.0"}}`))
	if findings := (langflowToolGuardCodeInjection{}).Apply(doc); len(findings) != 0 {
		t.Fatalf("got %d findings, want 0", len(findings))
	}
}

func TestLangflowToolGuardCodeInjection_AllowsBeforeAffectedRange(t *testing.T) {
	doc := parse.Parse("requirements.txt", []byte("langflow==0.6.19\n"))
	if findings := (langflowToolGuardCodeInjection{}).Apply(doc); len(findings) != 0 {
		t.Fatalf("got %d findings, want 0", len(findings))
	}
}

func TestLangflowToolGuardCodeInjection_AllowsFixedVersion(t *testing.T) {
	doc := parse.Parse("requirements.txt", []byte("langflow==1.10.1\n"))
	if findings := (langflowToolGuardCodeInjection{}).Apply(doc); len(findings) != 0 {
		t.Fatalf("got %d findings, want 0", len(findings))
	}
}

func TestLangflowToolGuardCodeInjection_AllowsRangeStartingAtFixedVersion(t *testing.T) {
	doc := parse.Parse("requirements.txt", []byte("langflow>=1.10.1\n"))
	if findings := (langflowToolGuardCodeInjection{}).Apply(doc); len(findings) != 0 {
		t.Fatalf("got %d findings, want 0", len(findings))
	}
}
