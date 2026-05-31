package builtin

import (
	"fmt"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

type gitlabMCPServerUnauthHTTP struct{}

func (gitlabMCPServerUnauthHTTP) ID() string { return "gitlab-mcp-server-unauth-http" }
func (gitlabMCPServerUnauthHTTP) Title() string {
	return "GitLab MCP Server exposes unauthenticated HTTP transport"
}
func (gitlabMCPServerUnauthHTTP) Severity() finding.Severity { return finding.SeverityCritical }
func (gitlabMCPServerUnauthHTTP) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (gitlabMCPServerUnauthHTTP) Formats() []parse.Format    { return parse.AllMCPFormats() }

func (gitlabMCPServerUnauthHTTP) Apply(doc *parse.Document) []finding.Finding {
	servers := parse.NormalizeMCPServers(doc)
	if len(servers) == 0 {
		return nil
	}
	var out []finding.Finding
	for _, s := range servers {
		if s.Disabled {
			continue
		}
		pkg, version, ok := gitlabMCPInvocation(s.Command, s.Args)
		if !ok || !vulnerableGitlabMCPServerVersion(version) || !gitlabMCPHTTPTransport(s) {
			continue
		}
		out = append(out, gitlabMCPServerUnauthHTTPFinding(doc.Path, s.Line, s.Name, pkg, version, s.Args))
	}
	return out
}

func gitlabMCPInvocation(command string, args []string) (pkg string, version string, ok bool) {
	candidates := append([]string{command}, args...)
	for _, raw := range candidates {
		name, ver, matched := splitGitlabMCPPackageSpec(raw)
		if matched {
			return name, ver, true
		}
	}
	return "", "", false
}

func splitGitlabMCPPackageSpec(raw string) (pkg string, version string, ok bool) {
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
	case "@yoda.digital/gitlab-mcp-server", "mcp-gitlab-server", "gitlab-mcp-server":
		return normalized, ver, true
	default:
		return "", "", false
	}
}

func vulnerableGitlabMCPServerVersion(raw string) bool {
	// CVE-2026-44895 is fixed in @yoda.digital/gitlab-mcp-server 0.6.0. OSV
	// covers pure package-version exposure, so this native rule only fires when
	// the vulnerable package is also configured for the risky HTTP/SSE transport.
	return vulnerableVersionBefore(raw, []int{0, 6, 0})
}

func gitlabMCPHTTPTransport(s parse.NormalizedMCPServer) bool {
	if s.URL != "" {
		return false
	}
	for _, arg := range s.Args {
		la := strings.ToLower(strings.TrimSpace(arg))
		if la == "--transport=http" || la == "--transport=sse" || la == "--transport" || la == "http" || la == "sse" || la == "--sse" || la == "--http" {
			return true
		}
		if strings.Contains(la, "transport") && (strings.Contains(la, "http") || strings.Contains(la, "sse")) {
			return true
		}
	}
	return false
}

func gitlabMCPServerUnauthHTTPFinding(path string, line int, serverName, pkg, version string, args []string) finding.Finding {
	match := pkg
	if version != "" {
		match = fmt.Sprintf("%s@%s", pkg, version)
	}
	if len(args) > 0 {
		match = fmt.Sprintf("%s args=%q", match, strings.Join(args, " "))
	}
	return finding.New(finding.Args{
		RuleID:       "gitlab-mcp-server-unauth-http",
		Severity:     finding.SeverityCritical,
		Taxonomy:     finding.TaxDetectable,
		Title:        "GitLab MCP Server before 0.6.0 is configured for unauthenticated HTTP/SSE transport",
		Description:  fmt.Sprintf("CVE-2026-44895: MCP server %q invokes GitLab MCP Server before 0.6.0 with HTTP/SSE transport. Affected versions expose a stateful GitLab-backed MCP endpoint with no inbound authentication and wildcard CORS, allowing cross-origin clients to use the operator's GitLab token-backed tools.", serverName),
		Path:         path,
		Line:         line,
		Match:        match,
		SuggestedFix: "Upgrade @yoda.digital/gitlab-mcp-server to 0.6.0 or later. Until upgraded, remove HTTP/SSE transport exposure or bind it to a locally protected interface with an authentication proxy.",
		Tags:         []string{"cve", "mcp", "gitlab", "http-transport", "auth-bypass"},
	})
}
