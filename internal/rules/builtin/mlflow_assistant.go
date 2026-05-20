package builtin

import (
	"fmt"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

type mlflowAssistantOriginBypass struct{}

func (mlflowAssistantOriginBypass) ID() string { return "mlflow-assistant-origin-bypass" }
func (mlflowAssistantOriginBypass) Title() string {
	return "MLflow Assistant version is vulnerable to local origin validation bypass"
}
func (mlflowAssistantOriginBypass) Severity() finding.Severity { return finding.SeverityCritical }
func (mlflowAssistantOriginBypass) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (mlflowAssistantOriginBypass) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest}
}

func (mlflowAssistantOriginBypass) Apply(doc *parse.Document) []finding.Finding {
	if doc.DependencyManifest == nil {
		return nil
	}
	for _, dep := range doc.DependencyManifest.Dependencies {
		if isMLflowPackage(dep.Name) && vulnerableMLflowAssistantVersion(dep.Version) {
			return []finding.Finding{mlflowAssistantOriginBypassFinding(doc.Path, dep.Line, fmt.Sprintf("%s@%s", dep.Name, dep.Version))}
		}
	}
	return nil
}

func isMLflowPackage(name string) bool {
	return strings.EqualFold(strings.TrimSpace(name), "mlflow")
}

func vulnerableMLflowAssistantVersion(raw string) bool {
	v := strings.TrimSpace(raw)
	if v == "" || strings.ContainsAny(v, "*xX") || strings.HasPrefix(v, "git+") || strings.HasPrefix(v, "file:") || strings.HasPrefix(v, "workspace:") {
		return false
	}
	m := packageVersionRE.FindString(v)
	if m == "" {
		return false
	}
	return compareVersionParts(m, []int{3, 9, 0}) >= 0 && compareVersionParts(m, []int{3, 10, 0}) < 0
}

func mlflowAssistantOriginBypassFinding(path string, line int, match string) finding.Finding {
	return finding.New(finding.Args{
		RuleID:       "mlflow-assistant-origin-bypass",
		Severity:     finding.SeverityCritical,
		Taxonomy:     finding.TaxDetectable,
		Title:        "MLflow Assistant 3.9.x exposes local ajax-api endpoints to cross-origin requests",
		Description:  "CVE-2026-2611: MLflow 3.9.0 introduced improper origin validation in Assistant /ajax-api endpoints, allowing a malicious webpage to interact with a victim's local MLflow Assistant and modify configuration to enable arbitrary command execution through the Claude Code sub-agent.",
		Path:         path,
		Line:         line,
		Match:        match,
		SuggestedFix: "Upgrade MLflow to 3.10.0 or later and review local Assistant configuration for unexpected Claude Code sub-agent access before restarting trusted agent workflows.",
		Tags:         []string{"cve", "mlflow", "python", "dependency-manifest", "origin-validation", "command-execution"},
	})
}
