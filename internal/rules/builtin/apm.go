package builtin

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

type microsoftAPMPluginComponentTraversal struct{}

func (microsoftAPMPluginComponentTraversal) ID() string {
	return "microsoft-apm-plugin-component-traversal"
}
func (microsoftAPMPluginComponentTraversal) Title() string {
	return "Microsoft APM plugin manifest references files outside the plugin directory"
}
func (microsoftAPMPluginComponentTraversal) Severity() finding.Severity { return finding.SeverityHigh }
func (microsoftAPMPluginComponentTraversal) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (microsoftAPMPluginComponentTraversal) Formats() []parse.Format {
	return []parse.Format{parse.FormatAPMPluginManifest}
}

func (microsoftAPMPluginComponentTraversal) Apply(doc *parse.Document) []finding.Finding {
	var top map[string]any
	if err := json.Unmarshal(doc.Raw, &top); err != nil {
		return nil
	}
	var findings []finding.Finding
	for _, field := range []string{"agents", "skills", "commands", "hooks"} {
		value, ok := top[field]
		if !ok {
			continue
		}
		for _, ref := range collectAPMComponentRefs(value) {
			if !apmComponentPathEscapesPlugin(ref) {
				continue
			}
			findings = append(findings, finding.New(finding.Args{
				RuleID:        microsoftAPMPluginComponentTraversal{}.ID(),
				Severity:      finding.SeverityHigh,
				Taxonomy:      finding.TaxDetectable,
				Title:         microsoftAPMPluginComponentTraversal{}.Title(),
				Description:   "CVE-2026-44641: Microsoft APM before 0.8.12 copied plugin components named in plugin.json fields such as agents, skills, commands, and hooks into .apm/ without enforcing that those paths stayed inside the plugin directory. Absolute paths or ../ traversal can copy arbitrary readable host files during apm install.",
				Path:          doc.Path,
				Line:          lineNumberForRawValue(doc.Raw, ref),
				Match:         fmt.Sprintf("%s: %s", field, ref),
				SuggestedFix:  "Upgrade Microsoft APM to 0.8.12 or later. Remove absolute paths, Windows drive/UNC paths, and ../ traversal from plugin.json component references; component paths should be relative paths inside the plugin directory.",
				Tags:          []string{"cve", "CVE-2026-44641", "microsoft-apm", "plugin-json", "path-traversal", "arbitrary-file-copy"},
				DedupGroupKey: "cve:CVE-2026-44641:microsoft-apm-plugin-component-traversal",
			}))
		}
	}
	return findings
}

func collectAPMComponentRefs(v any) []string {
	var out []string
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case string:
			if strings.TrimSpace(t) != "" {
				out = append(out, t)
			}
		case []any:
			for _, item := range t {
				walk(item)
			}
		case map[string]any:
			for _, item := range t {
				walk(item)
			}
		}
	}
	walk(v)
	return out
}

var windowsDrivePath = regexp.MustCompile(`^[A-Za-z]:[\\/]`)

func apmComponentPathEscapesPlugin(raw string) bool {
	p := strings.TrimSpace(raw)
	if p == "" {
		return false
	}
	if filepath.IsAbs(p) || strings.HasPrefix(p, "\\\\") || windowsDrivePath.MatchString(p) {
		return true
	}
	p = strings.ReplaceAll(p, "\\", "/")
	cleaned := filepath.ToSlash(filepath.Clean(p))
	return cleaned == ".." || strings.HasPrefix(cleaned, "../")
}

func lineNumberForRawValue(raw []byte, needle string) int {
	if needle == "" {
		return 0
	}
	text := string(raw)
	idx := strings.Index(text, needle)
	if idx < 0 {
		if encoded, err := json.Marshal(needle); err == nil {
			idx = strings.Index(text, strings.Trim(string(encoded), "\""))
		}
	}
	if idx < 0 {
		return 0
	}
	return strings.Count(text[:idx], "\n") + 1
}
