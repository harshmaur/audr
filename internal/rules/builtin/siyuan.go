package builtin

import (
	"fmt"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

type siYuanAnonymousPublishMCPAdminBypass struct{}

func (siYuanAnonymousPublishMCPAdminBypass) ID() string {
	return "siyuan-anonymous-publish-mcp-admin-bypass"
}
func (siYuanAnonymousPublishMCPAdminBypass) Title() string {
	return "SiYuan anonymous Publish can expose administrator MCP tools"
}
func (siYuanAnonymousPublishMCPAdminBypass) Severity() finding.Severity {
	return finding.SeverityCritical
}
func (siYuanAnonymousPublishMCPAdminBypass) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (siYuanAnonymousPublishMCPAdminBypass) Formats() []parse.Format {
	return []parse.Format{parse.FormatSiYuanConfig}
}

func (siYuanAnonymousPublishMCPAdminBypass) Apply(doc *parse.Document) []finding.Finding {
	cfg := doc.SiYuanConfig
	if cfg == nil || !cfg.Publish.Enable || cfg.Publish.Auth.Enable ||
		!vulnerableVersionBefore(cfg.System.KernelVersion, []int{3, 7, 2}) {
		return nil
	}
	return []finding.Finding{finding.New(finding.Args{
		RuleID:       "siyuan-anonymous-publish-mcp-admin-bypass",
		Severity:     finding.SeverityCritical,
		Taxonomy:     finding.TaxDetectable,
		Title:        "SiYuan anonymous Publish exposes administrator MCP tools",
		Description:  "CVE-2026-66012: SiYuan before 3.7.2 checks /mcp authentication but not the required administrator role or read-only state. Anonymous Publish injects a reader JWT into proxied requests, allowing unauthenticated callers to invoke administrator-level workspace file and plugin tools.",
		Path:         doc.Path,
		Line:         findLineContaining(doc.Raw, `"publish"`),
		Match:        fmt.Sprintf("SiYuan %s with publish.enable=true and publish.auth.enable=false", cfg.System.KernelVersion),
		SuggestedFix: "Upgrade SiYuan to 3.7.2 or later. Until upgraded, disable Publish or require Publish authentication, then review workspace plugins and rotate secrets stored in conf/conf.json.",
		Tags:         []string{"cve", "siyuan", "mcp", "missing-authorization", "anonymous-publish"},
	})}
}
