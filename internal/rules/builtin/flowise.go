package builtin

import (
	"fmt"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

type flowiseCustomMCPMissingAuth struct{}

func (flowiseCustomMCPMissingAuth) ID() string { return "flowise-custom-mcp-missing-auth" }
func (flowiseCustomMCPMissingAuth) Title() string {
	return "Flowise Custom MCP deployment leaves built-in authentication blank"
}
func (flowiseCustomMCPMissingAuth) Severity() finding.Severity { return finding.SeverityCritical }
func (flowiseCustomMCPMissingAuth) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (flowiseCustomMCPMissingAuth) Formats() []parse.Format    { return []parse.Format{parse.FormatEnv} }

func (flowiseCustomMCPMissingAuth) Apply(doc *parse.Document) []finding.Finding {
	if doc.Env == nil {
		return nil
	}
	if !looksLikeFlowiseEnv(doc.Env.Vars) {
		return nil
	}

	var out []finding.Finding
	for _, key := range []string{"FLOWISE_USERNAME", "FLOWISE_PASSWORD"} {
		value, ok := doc.Env.Vars[key]
		if !ok {
			continue
		}
		if strings.TrimSpace(value) != "" {
			continue
		}
		line := doc.Env.Lines[key]
		out = append(out, flowiseCustomMCPMissingAuthFinding(doc.Path, line, fmt.Sprintf("%s=", key)))
	}
	return out
}

func looksLikeFlowiseEnv(vars map[string]string) bool {
	for key, value := range vars {
		upperKey := strings.ToUpper(strings.TrimSpace(key))
		lowerValue := strings.ToLower(strings.TrimSpace(value))
		if strings.HasPrefix(upperKey, "FLOWISE_") || strings.Contains(lowerValue, "flowise") || strings.Contains(lowerValue, "custommcp") || strings.Contains(lowerValue, "custom_mcp") {
			return true
		}
	}
	return false
}

func flowiseCustomMCPMissingAuthFinding(path string, line int, match string) finding.Finding {
	return finding.New(finding.Args{
		RuleID:       "flowise-custom-mcp-missing-auth",
		Severity:     finding.SeverityCritical,
		Taxonomy:     finding.TaxDetectable,
		Title:        "Flowise Custom MCP auth is explicitly blank",
		Description:  "CVE-2025-71336: Flowise before 3.0.6 can execute arbitrary commands through the Custom MCP node-load endpoint, and default/blank FLOWISE_USERNAME or FLOWISE_PASSWORD leaves deployments without the built-in authentication barrier.",
		Path:         path,
		Line:         line,
		Match:        match,
		SuggestedFix: "Upgrade Flowise to 3.0.6 or later and set non-empty FLOWISE_USERNAME and FLOWISE_PASSWORD (or another strong authentication layer) before enabling Custom MCP or exposing Flowise beyond localhost.",
		Tags:         []string{"cve", "flowise", "mcp", "env", "authentication", "rce"},
	})
}
