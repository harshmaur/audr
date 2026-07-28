package builtin

import (
	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

type openclawHostExecGitExtTransportFiltering struct{}

func (openclawHostExecGitExtTransportFiltering) ID() string {
	return "openclaw-host-exec-git-ext-transport-filtering"
}
func (openclawHostExecGitExtTransportFiltering) Title() string {
	return "OpenClaw host exec environment filtering permits Git ext transport abuse"
}
func (openclawHostExecGitExtTransportFiltering) Severity() finding.Severity {
	return finding.SeverityHigh
}
func (openclawHostExecGitExtTransportFiltering) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (openclawHostExecGitExtTransportFiltering) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest, parse.FormatPackageJSON}
}
func (openclawHostExecGitExtTransportFiltering) Apply(doc *parse.Document) []finding.Finding {
	return openclawPackageVersionFindings(
		doc,
		func(raw string) bool { return vulnerableOpenClawVersionBefore(raw, []int{2026, 6, 6}) },
		openclawHostExecGitExtTransportFilteringFinding,
	)
}

func openclawHostExecGitExtTransportFilteringFinding(path, match string) finding.Finding {
	return openclawBacklogFinding(
		path,
		match,
		"openclaw-host-exec-git-ext-transport-filtering",
		finding.SeverityHigh,
		"OpenClaw before 2026.6.6 permits Git ext transport abuse through host exec",
		"CVE-2026-62200: OpenClaw before 2026.6.6 incompletely filters the host exec environment, allowing Git ext transport abuse that can execute or persist actions beyond the caller's intended authorization.",
		"Upgrade OpenClaw to 2026.6.6 or later and review host exec environment policy and recent Git transport activity.",
		[]string{"cve", "openclaw", "dependency-manifest", "host-exec", "git-ext", "authorization-bypass"},
	)
}

type openclawInterpreterStartupEnvFiltering struct{}

func (openclawInterpreterStartupEnvFiltering) ID() string {
	return "openclaw-interpreter-startup-env-filtering"
}
func (openclawInterpreterStartupEnvFiltering) Title() string {
	return "OpenClaw host exec filtering misses interpreter startup variables"
}
func (openclawInterpreterStartupEnvFiltering) Severity() finding.Severity {
	return finding.SeverityHigh
}
func (openclawInterpreterStartupEnvFiltering) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (openclawInterpreterStartupEnvFiltering) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest, parse.FormatPackageJSON}
}
func (openclawInterpreterStartupEnvFiltering) Apply(doc *parse.Document) []finding.Finding {
	return openclawPackageVersionFindings(
		doc,
		func(raw string) bool { return vulnerableOpenClawVersionBefore(raw, []int{2026, 6, 6}) },
		openclawInterpreterStartupEnvFilteringFinding,
	)
}

func openclawInterpreterStartupEnvFilteringFinding(path, match string) finding.Finding {
	return openclawBacklogFinding(
		path,
		match,
		"openclaw-interpreter-startup-env-filtering",
		finding.SeverityHigh,
		"OpenClaw before 2026.6.6 can pass unsafe interpreter startup variables to host exec",
		"CVE-2026-62199: OpenClaw before 2026.6.6 incompletely filters interpreter startup environment variables, allowing lower-trust input to execute or persist actions beyond the caller's intended authorization.",
		"Upgrade OpenClaw to 2026.6.6 or later and review host exec environment policy and recent interpreter startup activity.",
		[]string{"cve", "openclaw", "dependency-manifest", "host-exec", "environment", "command-injection"},
	)
}
