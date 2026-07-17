package builtin

import (
	"fmt"
	"net/url"
	pathpkg "path"
	"path/filepath"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
	"gopkg.in/yaml.v3"
)

type kiotaPluginStaticTemplateTraversal struct{}

func (kiotaPluginStaticTemplateTraversal) ID() string {
	return "kiota-plugin-static-template-traversal"
}
func (kiotaPluginStaticTemplateTraversal) Title() string {
	return "Kiota OpenAPI plugin template references a path outside the plugin package"
}
func (kiotaPluginStaticTemplateTraversal) Severity() finding.Severity {
	return finding.SeverityCritical
}
func (kiotaPluginStaticTemplateTraversal) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (kiotaPluginStaticTemplateTraversal) Formats() []parse.Format {
	return []parse.Format{parse.FormatKiotaOpenAPISpec}
}

type kiotaTemplateRef struct {
	kind string
	file string
}

func (kiotaPluginStaticTemplateTraversal) Apply(doc *parse.Document) []finding.Finding {
	var top map[string]any
	if err := yaml.Unmarshal(doc.Raw, &top); err != nil {
		return nil
	}
	if top["openapi"] == nil && top["swagger"] == nil {
		return nil
	}

	var refs []kiotaTemplateRef
	collectKiotaTemplateRefs(top, &refs)
	findings := make([]finding.Finding, 0, len(refs))
	for _, ref := range refs {
		if !kiotaStaticTemplatePathUnsafe(ref.file) {
			continue
		}
		findings = append(findings, finding.New(finding.Args{
			RuleID:       kiotaPluginStaticTemplateTraversal{}.ID(),
			Severity:     finding.SeverityCritical,
			Taxonomy:     finding.TaxDetectable,
			Title:        kiotaPluginStaticTemplateTraversal{}.Title(),
			Description:  "CVE-2026-59864: Kiota before 1.32.5 copied attacker-controlled static_template.file values from x-ai-adaptive-card and x-ai-capabilities into generated Microsoft 365 Copilot or Teams plugin manifests without validating that the path stayed inside the plugin package.",
			Path:         doc.Path,
			Line:         lineNumberForRawValue(doc.Raw, ref.file),
			Match:        fmt.Sprintf("%s file: %s", ref.kind, ref.file),
			SuggestedFix: "Upgrade Kiota to 1.32.5 or later, regenerate the plugin, and replace traversal, absolute, rooted, UNC, drive-letter, or URI template references with relative paths confined to the plugin package.",
			Tags:         []string{"cve", "CVE-2026-59864", "kiota", "openapi", "copilot-plugin", "path-traversal"},
		}))
	}
	return findings
}

func collectKiotaTemplateRefs(value any, refs *[]kiotaTemplateRef) {
	switch node := value.(type) {
	case map[string]any:
		if adaptive, ok := node["x-ai-adaptive-card"].(map[string]any); ok {
			title, _ := adaptive["title"].(string)
			file, _ := adaptive["file"].(string)
			if strings.TrimSpace(title) != "" && strings.TrimSpace(file) != "" {
				*refs = append(*refs, kiotaTemplateRef{kind: "x-ai-adaptive-card", file: file})
			}
		}
		if capabilities, ok := node["x-ai-capabilities"]; ok {
			collectKiotaCapabilityTemplateRefs(capabilities, refs)
		}
		for _, child := range node {
			collectKiotaTemplateRefs(child, refs)
		}
	case []any:
		for _, child := range node {
			collectKiotaTemplateRefs(child, refs)
		}
	}
}

func collectKiotaCapabilityTemplateRefs(value any, refs *[]kiotaTemplateRef) {
	switch node := value.(type) {
	case map[string]any:
		if semantics, ok := node["response_semantics"].(map[string]any); ok {
			if template, ok := semantics["static_template"].(map[string]any); ok {
				if file, ok := template["file"].(string); ok && strings.TrimSpace(file) != "" {
					*refs = append(*refs, kiotaTemplateRef{kind: "x-ai-capabilities static_template", file: file})
				}
			}
		}
		for _, child := range node {
			collectKiotaCapabilityTemplateRefs(child, refs)
		}
	case []any:
		for _, child := range node {
			collectKiotaCapabilityTemplateRefs(child, refs)
		}
	}
}

func kiotaStaticTemplatePathUnsafe(raw string) bool {
	p := strings.TrimSpace(raw)
	if p == "" {
		return false
	}
	if filepath.IsAbs(p) || strings.HasPrefix(p, `\`) || windowsDrivePath.MatchString(p) {
		return true
	}
	if parsed, err := url.Parse(p); err == nil && (parsed.IsAbs() || parsed.Host != "") {
		return true
	}
	normalized := strings.ReplaceAll(p, `\`, "/")
	cleaned := pathpkg.Clean(normalized)
	return cleaned == ".." || strings.HasPrefix(cleaned, "../")
}
