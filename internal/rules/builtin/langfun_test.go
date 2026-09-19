package builtin

import (
	"strings"
	"testing"

	"github.com/harshmaur/audr/internal/parse"
	"github.com/harshmaur/audr/internal/rules"
)

func TestLangfunQueryEvalInjection_VulnerableRequirement(t *testing.T) {
	doc := parse.Parse("requirements.txt", []byte("langfun==0.1.1\n"))
	findings := langfunQueryEvalInjection{}.Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if got := findings[0]; got.RuleID != "langfun-query-eval-injection" || got.Line != 1 {
		t.Fatalf("finding = %#v, want langfun-query-eval-injection at line 1", got)
	}
	if !strings.Contains(findings[0].Description, "CVE-2026-75062") {
		t.Fatalf("description = %q, want CVE-specific metadata", findings[0].Description)
	}
}

func TestLangfunQueryEvalInjection_VulnerablePyprojectRange(t *testing.T) {
	doc := parse.Parse("pyproject.toml", []byte("[project]\ndependencies = [\"langfun>=0.0.1,<0.1.2\"]\n"))
	rule := langfunQueryEvalInjection{}
	if findings := rule.Apply(doc); len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
}

func TestLangfunQueryEvalInjection_FixedAndPreAffectedVersionsDoNotFire(t *testing.T) {
	rule := langfunQueryEvalInjection{}
	for _, raw := range []string{"langfun==0.1.2\n", "langfun==0.0.0\n", "langfun<0.0.1\n"} {
		doc := parse.Parse("requirements.txt", []byte(raw))
		if findings := rule.Apply(doc); len(findings) != 0 {
			t.Fatalf("%q produced %d findings, want 0", raw, len(findings))
		}
	}
}

func TestLangfunQueryEvalInjection_Registered(t *testing.T) {
	doc := parse.Parse("requirements.txt", []byte("langfun==0.1.1\n"))
	for _, rule := range rules.All() {
		if rule.ID() == "langfun-query-eval-injection" {
			if findings := rule.Apply(doc); len(findings) != 1 {
				t.Fatalf("registered rule findings = %d, want 1", len(findings))
			}
			return
		}
	}
	t.Fatal("langfun-query-eval-injection is not registered")
}
