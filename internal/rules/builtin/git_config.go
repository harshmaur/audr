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
		if !dangerousGitConfigExecKey(fullKey) || !gitConfigKeyValueLooksExecutable(fullKey, value) {
			continue
		}
		description, suggestedFix, tags := gitConfigExecMetadata(doc.Path, fullKey)
		out = append(out, finding.New(finding.Args{
			RuleID:        "copilot-cli-nested-git-config-exec",
			Severity:      finding.SeverityHigh,
			Taxonomy:      finding.TaxDetectable,
			Title:         "Executable git config key can run during agent git operations",
			Description:   description,
			Path:          doc.Path,
			Line:          i + 1,
			Match:         fullKey,
			Context:       strings.TrimSpace(raw),
			SuggestedFix:  suggestedFix,
			Tags:          tags,
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

func gitConfigKeyValueLooksExecutable(key, value string) bool {
	v := strings.TrimSpace(strings.ToLower(value))
	switch key {
	case "core.hookspath":
		return v != "" && v != "/dev/null" && v != "nul"
	case "core.fsmonitor":
		return v != "" && v != "true" && v != "false"
	default:
		return gitConfigValueLooksExecutable(value)
	}
}

func gitConfigExecMetadata(configPath, key string) (string, string, []string) {
	descriptions := make([]string, 0, 2)
	fixes := make([]string, 0, 3)
	tags := []string{"ai-coding-agent", "git-config", "command-execution"}
	cveTagged := false

	if nestedBareGitConfig(configPath) {
		descriptions = append(descriptions, "CVE-2026-45033: GitHub Copilot CLI before 1.0.43 could execute attacker-controlled helpers from nested bare-repository Git config.")
		fixes = append(fixes, "Upgrade GitHub Copilot CLI to 1.0.43 or later.")
		tags = append(tags, "cve", "github-copilot-cli")
		cveTagged = true
	}

	switch key {
	case "core.hookspath":
		descriptions = append(descriptions, "CVE-2026-19590: OpenAI Codex Desktop on Windows and macOS could execute repository-local core.hooksPath hooks while inspecting repositories delivered with local Git config intact.")
		fixes = append(fixes, "Update OpenAI Codex Desktop on Windows and macOS to a release that mitigates repository-local hook execution during automated Git inspection.")
		tags = append(tags, "openai-codex")
	case "core.fsmonitor":
		descriptions = append(descriptions, "CVE-2026-19592: OpenAI Codex CLI on Windows, macOS, and Linux and Codex Desktop on Windows and macOS could execute repository-local core.fsmonitor helpers while collecting Git metadata from repositories delivered with local Git config intact.")
		fixes = append(fixes, "Update OpenAI Codex CLI on Windows, macOS, and Linux and Codex Desktop on Windows and macOS to a release that mitigates repository-local fsmonitor execution during automated Git inspection.")
		tags = append(tags, "openai-codex")
	}

	if (key == "core.hookspath" || key == "core.fsmonitor") && !cveTagged {
		tags = append(tags, "cve")
	}
	if len(descriptions) == 0 {
		descriptions = append(descriptions, "Executable repository-local Git config can run attacker-controlled commands during automated agent Git operations.")
	}
	fixes = append(fixes, "Remove nested bare repositories or unset executable Git config keys such as core.fsmonitor, core.hookspath, diff.external, and merge.tool before allowing an agent to run Git commands in this workspace.")
	return strings.Join(descriptions, " "), strings.Join(fixes, " "), tags
}

func nestedBareGitConfig(configPath string) bool {
	normalized := filepath.ToSlash(strings.ReplaceAll(configPath, `\`, "/"))
	parent := strings.ToLower(filepath.Base(filepath.Dir(normalized)))
	return parent != ".git" && strings.HasSuffix(parent, ".git")
}
