package builtin

import (
	"path/filepath"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

type copilotCLINestedGitConfigExec struct{}

func (copilotCLINestedGitConfigExec) ID() string { return "copilot-cli-nested-git-config-exec" }
func (copilotCLINestedGitConfigExec) Title() string {
	return "Git config can execute commands during agent git operations"
}
func (copilotCLINestedGitConfigExec) Severity() finding.Severity { return finding.SeverityHigh }
func (copilotCLINestedGitConfigExec) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (copilotCLINestedGitConfigExec) Formats() []parse.Format {
	return []parse.Format{parse.FormatGitConfig}
}

func (copilotCLINestedGitConfigExec) Apply(doc *parse.Document) []finding.Finding {
	if doc.Format != parse.FormatGitConfig {
		return nil
	}
	var out []finding.Finding
	section := ""
	for i, raw := range strings.Split(string(doc.Raw), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.Contains(line, "]") {
			section = normalizeGitConfigSection(line)
			continue
		}
		key, value, ok := splitGitConfigAssignment(line)
		if !ok {
			continue
		}
		fullKey := gitConfigFullKey(section, key)
		if !dangerousGitConfigExecKey(fullKey) || !gitConfigValueLooksExecutable(value) {
			continue
		}
		out = append(out, finding.New(finding.Args{
			RuleID:        "copilot-cli-nested-git-config-exec",
			Severity:      finding.SeverityHigh,
			Taxonomy:      finding.TaxDetectable,
			Title:         "Executable git config key can run during agent git operations",
			Description:   "CVE-2026-45033: GitHub Copilot CLI before 1.0.43 could execute attacker-controlled commands when git discovered a nested bare repository with executable git config keys during normal operations.",
			Path:          doc.Path,
			Line:          i + 1,
			Match:         fullKey,
			Context:       strings.TrimSpace(raw),
			SuggestedFix:  "Upgrade GitHub Copilot CLI to 1.0.43 or later. Remove nested bare repositories or unset executable git config keys such as core.fsmonitor, core.hookspath, diff.external, and merge.tool before allowing an agent to run git commands in this workspace.",
			Tags:          []string{"cve", "github-copilot-cli", "git-config", "command-execution"},
			DedupGroupKey: "git-config-exec:" + filepath.ToSlash(doc.Path) + ":" + fullKey,
		}))
	}
	return out
}

func normalizeGitConfigSection(line string) string {
	end := strings.Index(line, "]")
	if end < 0 {
		return ""
	}
	section := strings.TrimSpace(line[1:end])
	section = strings.Trim(section, `"`)
	fields := strings.Fields(section)
	if len(fields) == 0 {
		return ""
	}
	return strings.ToLower(fields[0])
}

func splitGitConfigAssignment(line string) (string, string, bool) {
	idx := strings.Index(line, "=")
	if idx < 0 {
		return "", "", false
	}
	key := strings.ToLower(strings.TrimSpace(line[:idx]))
	value := strings.TrimSpace(line[idx+1:])
	value = strings.Trim(value, `"'`)
	return key, value, key != "" && value != ""
}

func gitConfigFullKey(section, key string) string {
	if section == "" {
		return key
	}
	return section + "." + key
}

func dangerousGitConfigExecKey(key string) bool {
	switch key {
	case "core.fsmonitor", "core.hookspath", "diff.external", "merge.tool", "mergetool.cmd", "difftool.cmd", "core.editor", "sequence.editor", "gpg.program", "ssh.variant":
		return true
	}
	return strings.HasPrefix(key, "mergetool.") && strings.HasSuffix(key, ".cmd") || strings.HasPrefix(key, "difftool.") && strings.HasSuffix(key, ".cmd")
}

func gitConfigValueLooksExecutable(value string) bool {
	v := strings.TrimSpace(strings.ToLower(value))
	if v == "" || v == "true" || v == "false" || v == "none" || v == "noop" {
		return false
	}
	if strings.ContainsAny(v, "`|;&$<>") || strings.Contains(v, "$(") || strings.Contains(v, "${") {
		return true
	}
	if strings.Contains(v, "/") || strings.Contains(v, "\\") || strings.HasPrefix(v, "sh ") || strings.HasPrefix(v, "bash ") || strings.HasPrefix(v, "python") || strings.HasPrefix(v, "node ") || strings.HasPrefix(v, "powershell") || strings.HasPrefix(v, "pwsh ") || strings.HasPrefix(v, "cmd ") {
		return true
	}
	return false
}
