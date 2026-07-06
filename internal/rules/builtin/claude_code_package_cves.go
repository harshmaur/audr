package builtin

import (
	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

type claudeCodeWorktreeGitConfusion struct{}

func (claudeCodeWorktreeGitConfusion) ID() string {
	return "claude-code-worktree-git-confusion"
}
func (claudeCodeWorktreeGitConfusion) Title() string {
	return "Claude Code version is vulnerable to worktree Git directory confusion"
}
func (claudeCodeWorktreeGitConfusion) Severity() finding.Severity { return finding.SeverityHigh }
func (claudeCodeWorktreeGitConfusion) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (claudeCodeWorktreeGitConfusion) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest, parse.FormatPackageJSON}
}

func (claudeCodeWorktreeGitConfusion) Apply(doc *parse.Document) []finding.Finding {
	return dependencyVersionFinding(doc, isClaudeCodePackage, vulnerableClaudeCodeWorktreeGitConfusionVersion, claudeCodeWorktreeGitConfusionFinding)
}

func isClaudeCodePackage(name string) bool {
	n := normalizePackageName(name)
	return n == "@anthropic-ai/claude-code" || n == "claude-code"
}

func vulnerableClaudeCodeWorktreeGitConfusionVersion(raw string) bool {
	m := packageVersionRE.FindString(raw)
	if m == "" {
		return false
	}
	return compareVersionParts(m, []int{2, 1, 38}) >= 0 && compareVersionParts(m, []int{2, 1, 163}) < 0
}

func claudeCodeWorktreeGitConfusionFinding(path string, line int, match string) finding.Finding {
	return finding.New(finding.Args{
		RuleID:       "claude-code-worktree-git-confusion",
		Severity:     finding.SeverityHigh,
		Taxonomy:     finding.TaxDetectable,
		Title:        "Claude Code 2.1.38 through 2.1.162 allows worktree Git directory confusion",
		Description:  "CVE-2026-55607: Claude Code versions 2.1.38 before 2.1.163 mishandled worktrees named .git and worktrees outside the sandbox context, enabling Git directory confusion attacks through symlink manipulation and executable Git helper configuration.",
		Path:         path,
		Line:         line,
		Match:        match,
		SuggestedFix: "Upgrade @anthropic-ai/claude-code to 2.1.163 or later and audit any repositories opened with vulnerable Claude Code versions for unexpected worktrees, symlinks, and executable Git helper configuration.",
		Tags:         []string{"cve", "claude-code", "dependency-manifest", "git-config", "sandbox-escape"},
	})
}
