package builtin

import (
	"fmt"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

type langflowToolGuardCodeInjection struct{}

func (langflowToolGuardCodeInjection) ID() string { return "langflow-toolguard-code-injection" }
func (langflowToolGuardCodeInjection) Title() string {
	return "Langflow ToolGuard version is vulnerable to dynamic CodeInput injection"
}
func (langflowToolGuardCodeInjection) Severity() finding.Severity { return finding.SeverityCritical }
func (langflowToolGuardCodeInjection) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (langflowToolGuardCodeInjection) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest}
}
func (langflowToolGuardCodeInjection) Apply(doc *parse.Document) []finding.Finding {
	if doc.DependencyManifest == nil || doc.DependencyManifest.Ecosystem != "pypi" {
		return nil
	}
	return dependencyVersionFinding(doc, isLangflowPackage, vulnerableLangflowToolGuardVersion, langflowToolGuardCodeInjectionFinding)
}

func isLangflowPackage(name string) bool {
	return normalizePackageName(name) == "langflow"
}

type langflowVersionBound struct {
	version   string
	inclusive bool
}

func vulnerableLangflowToolGuardVersion(raw string) bool {
	v := strings.TrimSpace(raw)
	if v == "" || strings.ContainsAny(v, "*xX") || strings.HasPrefix(v, "git+") || strings.HasPrefix(v, "file:") || strings.HasPrefix(v, "workspace:") {
		return false
	}

	lower := langflowVersionBound{version: "1.0.0", inclusive: true}
	upper := langflowVersionBound{version: "1.10.1", inclusive: false}
	for _, rawClause := range strings.Split(v, ",") {
		clause := strings.TrimSpace(rawClause)
		version := packageVersionRE.FindString(clause)
		if version == "" {
			return false
		}
		op := strings.TrimSpace(clause[:strings.Index(clause, version)])
		switch op {
		case "", "=", "==", "===":
			lower = tighterLangflowLowerBound(lower, langflowVersionBound{version: version, inclusive: true})
			upper = tighterLangflowUpperBound(upper, langflowVersionBound{version: version, inclusive: true})
		case ">=":
			lower = tighterLangflowLowerBound(lower, langflowVersionBound{version: version, inclusive: true})
		case ">":
			lower = tighterLangflowLowerBound(lower, langflowVersionBound{version: version, inclusive: false})
		case "<=":
			upper = tighterLangflowUpperBound(upper, langflowVersionBound{version: version, inclusive: true})
		case "<":
			upper = tighterLangflowUpperBound(upper, langflowVersionBound{version: version, inclusive: false})
		case "~=":
			lower = tighterLangflowLowerBound(lower, langflowVersionBound{version: version, inclusive: true})
			compatibleUpper, ok := langflowCompatibleUpperBound(version)
			if !ok {
				return false
			}
			upper = tighterLangflowUpperBound(upper, langflowVersionBound{version: compatibleUpper, inclusive: false})
		case "!=":
			// Excluding one release does not remove the rest of the affected interval.
		default:
			return false
		}
	}

	cmp := compareLangflowVersions(lower.version, upper.version)
	return cmp < 0 || (cmp == 0 && lower.inclusive && upper.inclusive)
}

func tighterLangflowLowerBound(current, candidate langflowVersionBound) langflowVersionBound {
	cmp := compareLangflowVersions(candidate.version, current.version)
	if cmp > 0 || (cmp == 0 && !candidate.inclusive) {
		return candidate
	}
	return current
}

func tighterLangflowUpperBound(current, candidate langflowVersionBound) langflowVersionBound {
	cmp := compareLangflowVersions(candidate.version, current.version)
	if cmp < 0 || (cmp == 0 && !candidate.inclusive) {
		return candidate
	}
	return current
}

func langflowCompatibleUpperBound(version string) (string, bool) {
	parts := strings.Split(version, ".")
	values := make([]int, len(parts))
	for i, part := range parts {
		value, ok := atoiSmall(part)
		if !ok {
			return "", false
		}
		values[i] = value
	}
	bump := 0
	if len(values) >= 3 {
		bump = len(values) - 2
	}
	values[bump]++
	for i := bump + 1; i < len(values); i++ {
		values[i] = 0
	}
	formatted := make([]string, len(values))
	for i, value := range values {
		formatted[i] = fmt.Sprintf("%d", value)
	}
	return strings.Join(formatted, "."), true
}

func compareLangflowVersions(left, right string) int {
	parts := strings.Split(right, ".")
	fixed := make([]int, 0, len(parts))
	for _, part := range parts {
		value, ok := atoiSmall(part)
		if !ok {
			return 1
		}
		fixed = append(fixed, value)
	}
	return compareVersionParts(left, fixed)
}

func langflowToolGuardCodeInjectionFinding(path string, line int, match string) finding.Finding {
	return finding.New(finding.Args{
		RuleID:       "langflow-toolguard-code-injection",
		Severity:     finding.SeverityCritical,
		Taxonomy:     finding.TaxDetectable,
		Title:        "Langflow through 1.10.0 can execute unvalidated ToolGuard CodeInput fields",
		Description:  "CVE-2026-9135: Langflow OSS 1.0.0 through 1.10.0 validates the main component source but not dynamic CodeInput fields used to generate ToolGuard Python files, allowing stored server-side code execution despite allow_custom_components=false.",
		Path:         path,
		Line:         line,
		Match:        fmt.Sprintf("%s (affected Langflow range 1.0.0 through 1.10.0)", match),
		SuggestedFix: "Upgrade Langflow OSS to 1.10.1 or later, then review stored flows for unexpected ToolGuard dynamic CodeInput Python and audit use of update_flow_component_field across users.",
		Tags:         []string{"cve", "langflow", "toolguard", "dependency-manifest", "code-injection"},
	})
}
