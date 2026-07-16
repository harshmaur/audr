package builtin

import (
	"fmt"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

type mcpPythonSDKWebSocketOriginValidation struct{}

func (mcpPythonSDKWebSocketOriginValidation) ID() string {
	return "mcp-python-sdk-websocket-origin-validation"
}
func (mcpPythonSDKWebSocketOriginValidation) Title() string {
	return "MCP Python SDK WebSocket transport lacks Host and Origin validation"
}
func (mcpPythonSDKWebSocketOriginValidation) Severity() finding.Severity {
	return finding.SeverityHigh
}
func (mcpPythonSDKWebSocketOriginValidation) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (mcpPythonSDKWebSocketOriginValidation) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest}
}
func (mcpPythonSDKWebSocketOriginValidation) Apply(doc *parse.Document) []finding.Finding {
	if doc.DependencyManifest == nil || !strings.EqualFold(doc.DependencyManifest.Ecosystem, "pypi") {
		return nil
	}
	for _, dep := range doc.DependencyManifest.Dependencies {
		if normalizePackageName(dep.Name) != "mcp" || !vulnerableVersionBefore(dep.Version, []int{1, 28, 1}) {
			continue
		}
		return []finding.Finding{finding.New(finding.Args{
			RuleID:       "mcp-python-sdk-websocket-origin-validation",
			Severity:     finding.SeverityHigh,
			Taxonomy:     finding.TaxDetectable,
			Title:        "MCP Python SDK before 1.28.1 includes an origin-blind WebSocket transport",
			Description:  "CVE-2026-59950: the deprecated mcp.server.websocket.websocket_server transport in MCP Python SDK versions before 1.28.1 accepts WebSocket handshakes without Host or Origin validation, allowing untrusted browser origins to connect when an application exposes that transport.",
			Path:         doc.Path,
			Line:         dep.Line,
			Match:        fmt.Sprintf("%s@%s", dep.Name, dep.Version),
			SuggestedFix: "Upgrade the PyPI mcp package to 1.28.1 or later, migrate away from the deprecated WebSocket transport, and enforce explicit Host and Origin allowlists at the application or reverse proxy.",
			Tags:         []string{"cve", "mcp", "pypi", "dependency-manifest", "websocket", "origin-validation"},
		})}
	}
	return nil
}
