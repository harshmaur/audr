package builtin

import (
	"fmt"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

type codeRunnerMCPServerUnauthHTTP struct{}

func (codeRunnerMCPServerUnauthHTTP) ID() string { return "code-runner-mcp-unauth-http-rce" }
func (codeRunnerMCPServerUnauthHTTP) Title() string {
	return "Code Runner MCP Server exposes unauthenticated HTTP RCE"
}
func (codeRunnerMCPServerUnauthHTTP) Severity() finding.Severity { return finding.SeverityCritical }
func (codeRunnerMCPServerUnauthHTTP) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (codeRunnerMCPServerUnauthHTTP) Formats() []parse.Format    { return parse.AllMCPFormats() }

func (codeRunnerMCPServerUnauthHTTP) Apply(doc *parse.Document) []finding.Finding {
	servers := parse.NormalizeMCPServers(doc)
	if len(servers) == 0 {
		return nil
	}
	var out []finding.Finding
	for _, s := range servers {
		if s.Disabled {
			continue
		}
		pkg, version, ok := codeRunnerMCPInvocation(s.Command, s.Args)
		if !ok || !codeRunnerMCPHTTPTransport(s) {
			continue
		}
		out = append(out, codeRunnerMCPServerUnauthHTTPFinding(doc.Path, s.Line, s.Name, pkg, version, s.Args))
	}
	return out
}

func codeRunnerMCPInvocation(command string, args []string) (pkg string, version string, ok bool) {
	candidates := append([]string{command}, args...)
	for _, raw := range candidates {
		name, ver, matched := splitCodeRunnerMCPPackageSpec(raw)
		if matched {
			return name, ver, true
		}
	}
	return "", "", false
}

func splitCodeRunnerMCPPackageSpec(raw string) (pkg string, version string, ok bool) {
	s := strings.TrimSpace(strings.Trim(raw, "'\""))
	if s == "" {
		return "", "", false
	}
	for strings.HasPrefix(s, "npm:") {
		s = strings.TrimPrefix(s, "npm:")
	}
	name := s
	ver := ""
	if strings.HasPrefix(s, "@") {
		parts := strings.Split(s, "@")
		if len(parts) >= 3 {
			name = "@" + parts[1]
			ver = parts[2]
		}
	} else if i := strings.LastIndex(s, "@"); i > 0 {
		name = s[:i]
		ver = s[i+1:]
	}
	normalized := strings.ToLower(strings.ReplaceAll(name, "_", "-"))
	switch normalized {
	case "mcp-server-code-runner", "formulahendry/mcp-server-code-runner", "github:formulahendry/mcp-server-code-runner":
		return normalized, ver, true
	default:
		return "", "", false
	}
}

func codeRunnerMCPHTTPTransport(s parse.NormalizedMCPServer) bool {
	// A remote URL entry means the client connects to an already-running server;
	// the local posture we can honestly verify here is a stdio command configured
	// to launch Code Runner MCP Server with its unauthenticated HTTP transport.
	if s.URL != "" {
		return false
	}
	for i, arg := range s.Args {
		la := strings.ToLower(strings.TrimSpace(arg))
		if la == "--transport=http" || la == "--transport" || la == "http" || la == "--http" {
			return true
		}
		if la == "--port=3088" || la == "--port" && i+1 < len(s.Args) && strings.TrimSpace(s.Args[i+1]) == "3088" {
			return true
		}
		if strings.Contains(la, "transport") && strings.Contains(la, "http") {
			return true
		}
	}
	return false
}

func codeRunnerMCPServerUnauthHTTPFinding(path string, line int, serverName, pkg, version string, args []string) finding.Finding {
	match := pkg
	if version != "" {
		match = fmt.Sprintf("%s@%s", pkg, version)
	}
	if len(args) > 0 {
		match = fmt.Sprintf("%s args=%q", match, strings.Join(args, " "))
	}
	return finding.New(finding.Args{
		RuleID:       "code-runner-mcp-unauth-http-rce",
		Severity:     finding.SeverityCritical,
		Taxonomy:     finding.TaxDetectable,
		Title:        "Code Runner MCP Server is configured for unauthenticated HTTP transport",
		Description:  fmt.Sprintf("CVE-2026-5029: MCP server %q invokes Code Runner MCP Server with HTTP transport. Affected versions expose an unauthenticated /mcp JSON-RPC endpoint on port 3088 where remote callers can invoke the run-code tool and execute arbitrary code with the server user's privileges.", serverName),
		Path:         path,
		Line:         line,
		Match:        match,
		SuggestedFix: "Remove HTTP transport exposure for Code Runner MCP Server, use stdio-only local MCP integration, or protect any HTTP listener with loopback binding plus authentication before enabling run-code tools.",
		Tags:         []string{"cve", "mcp", "code-runner", "http-transport", "rce"},
	})
}
