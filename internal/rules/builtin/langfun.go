package builtin

import (
	"fmt"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

// langfunQueryEvalInjection identifies the published PyPI package range while
// OSV has no package coordinate for CVE-2026-75062. It intentionally limits
// detection to parsed PyPI manifests: the vulnerability is in langfun's
// default lf.query Python protocol, not generic Python evaluation.
type langfunQueryEvalInjection struct{}

func (langfunQueryEvalInjection) ID() string { return "langfun-query-eval-injection" }
func (langfunQueryEvalInjection) Title() string {
	return "langfun lf.query protocol can evaluate attacker-generated Python"
}
func (langfunQueryEvalInjection) Severity() finding.Severity { return finding.SeverityCritical }
func (langfunQueryEvalInjection) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (langfunQueryEvalInjection) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest}
}

func (langfunQueryEvalInjection) Apply(doc *parse.Document) []finding.Finding {
	if doc.DependencyManifest == nil || doc.DependencyManifest.Ecosystem != "pypi" {
		return nil
	}
	return dependencyVersionFinding(doc, isLangfunPackage, vulnerableLangfunQueryVersion, langfunQueryEvalInjectionFinding)
}

func isLangfunPackage(name string) bool { return normalizePackageName(name) == "langfun" }

// vulnerableLangfunQueryVersion returns true only when a manifest constraint
// intersects the vendor-published affected interval >=0.0.1,<0.1.2.
func vulnerableLangfunQueryVersion(raw string) bool {
	v := strings.TrimSpace(raw)
	if v == "" || strings.ContainsAny(v, "*xX") || strings.HasPrefix(v, "git+") || strings.HasPrefix(v, "file:") || strings.HasPrefix(v, "workspace:") {
		return false
	}

	lower := langfunVersionBound{version: "0.0.1", inclusive: true}
	upper := langfunVersionBound{version: "0.1.2", inclusive: false}
	for _, rawClause := range strings.Split(v, ",") {
		clause := strings.TrimSpace(rawClause)
		version := packageVersionRE.FindString(clause)
		if version == "" {
			return false
		}
		op := strings.TrimSpace(clause[:strings.Index(clause, version)])
		candidate := langfunVersionBound{version: version, inclusive: true}
		switch op {
		case "", "=", "==", "===":
			lower = tighterLangfunLowerBound(lower, candidate)
			upper = tighterLangfunUpperBound(upper, candidate)
		case ">=":
			lower = tighterLangfunLowerBound(lower, candidate)
		case ">":
			candidate.inclusive = false
			lower = tighterLangfunLowerBound(lower, candidate)
		case "<=":
			upper = tighterLangfunUpperBound(upper, candidate)
		case "<":
			candidate.inclusive = false
			upper = tighterLangfunUpperBound(upper, candidate)
		case "!=":
			// Excluding one release leaves the remaining affected interval.
		default:
			return false
		}
	}
	cmp := compareVersionParts(lower.version, versionParts(upper.version))
	return cmp < 0 || (cmp == 0 && lower.inclusive && upper.inclusive)
}

type langfunVersionBound struct {
	version   string
	inclusive bool
}

func tighterLangfunLowerBound(current, candidate langfunVersionBound) langfunVersionBound {
	cmp := compareVersionParts(candidate.version, versionParts(current.version))
	if cmp > 0 || (cmp == 0 && !candidate.inclusive) {
		return candidate
	}
	return current
}

func tighterLangfunUpperBound(current, candidate langfunVersionBound) langfunVersionBound {
	cmp := compareVersionParts(candidate.version, versionParts(current.version))
	if cmp < 0 || (cmp == 0 && !candidate.inclusive) {
		return candidate
	}
	return current
}

func versionParts(v string) []int {
	parts := strings.Split(v, ".")
	out := make([]int, len(parts))
	for i, part := range parts {
		n, ok := atoiSmall(part)
		if !ok {
			return []int{0}
		}
		out[i] = n
	}
	return out
}

func langfunQueryEvalInjectionFinding(path string, line int, match string) finding.Finding {
	return finding.New(finding.Args{
		RuleID:       "langfun-query-eval-injection",
		Severity:     finding.SeverityCritical,
		Taxonomy:     finding.TaxDetectable,
		Title:        "langfun before 0.1.2 can evaluate attacker-generated Python",
		Description:  "CVE-2026-75062: Google langfun versions 0.0.1 through 0.1.1 use unsandboxed dynamic evaluation in the default lf.query Python protocol. Crafted prompt input can cause the host application to evaluate generated Python expressions and execute code in its process.",
		Path:         path,
		Line:         line,
		Match:        fmt.Sprintf("%s (affected langfun range >=0.0.1,<0.1.2)", match),
		SuggestedFix: "Upgrade langfun to 0.1.2 or later. Until upgraded, do not expose default lf.query Python-protocol execution to untrusted prompt input and isolate any application that evaluates model-generated expressions.",
		Tags:         []string{"cve", "langfun", "python", "dependency-manifest", "eval-injection", "code-execution"},
	})
}
