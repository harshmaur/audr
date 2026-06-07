package builtin

import (
	"fmt"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

type claudeHUDComspecCommandInjection struct{}

func (claudeHUDComspecCommandInjection) ID() string { return "claude-hud-comspec-command-injection" }
func (claudeHUDComspecCommandInjection) Title() string {
	return "Claude HUD version is vulnerable to COMSPEC command injection"
}
func (claudeHUDComspecCommandInjection) Severity() finding.Severity { return finding.SeverityHigh }
func (claudeHUDComspecCommandInjection) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (claudeHUDComspecCommandInjection) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest, parse.FormatPackageJSON}
}

func (claudeHUDComspecCommandInjection) Apply(doc *parse.Document) []finding.Finding {
	if doc.DependencyManifest == nil {
		return nil
	}
	for _, dep := range doc.DependencyManifest.Dependencies {
		if isClaudeHUDPackage(dep.Name) && vulnerableClaudeHUDVersion(dep.Version) {
			return []finding.Finding{claudeHUDComspecCommandInjectionFinding(doc.Path, dep.Line, fmt.Sprintf("%s@%s", dep.Name, dep.Version))}
		}
	}
	return nil
}

func isClaudeHUDPackage(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.ReplaceAll(n, "_", "-")
	return n == "claude-hud" || n == "@anthropic-ai/claude-hud" || n == "@claude-hud/cli"
}

func vulnerableClaudeHUDVersion(raw string) bool {
	// CVE-2026-47092 affects Claude HUD through 0.0.12; the upstream patch is
	// commit-based in NVD, so treat the next semver patch as the first safe
	// packaged version unless a later advisory supplies a different fixed tag.
	return vulnerableVersionBefore(raw, []int{0, 0, 13})
}

func claudeHUDComspecCommandInjectionFinding(path string, line int, match string) finding.Finding {
	return finding.New(finding.Args{
		RuleID:       "claude-hud-comspec-command-injection",
		Severity:     finding.SeverityHigh,
		Taxonomy:     finding.TaxDetectable,
		Title:        "Claude HUD through 0.0.12 trusts COMSPEC during version checks",
		Description:  "CVE-2026-47092: Claude HUD through 0.0.12 performs a version check through the process COMSPEC on Windows without validating the executable path. A local attacker who controls COMSPEC before Claude HUD starts can cause arbitrary executable launch with cmd.exe-style arguments.",
		Path:         path,
		Line:         line,
		Match:        match,
		SuggestedFix: "Upgrade Claude HUD to a build after upstream commit 234d9aa / packaged version 0.0.13 or later, and clear any user or project environment that overrides COMSPEC before running Claude HUD.",
		Tags:         []string{"cve", "claude-hud", "dependency-manifest", "windows", "command-injection"},
	})
}
