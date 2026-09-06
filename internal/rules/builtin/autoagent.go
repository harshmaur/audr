package builtin

import (
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

type autoAgentUnauthTCPCommandServer struct{}

func (autoAgentUnauthTCPCommandServer) ID() string {
	return "autoagent-unauth-tcp-command-server"
}
func (autoAgentUnauthTCPCommandServer) Title() string {
	return "AutoAgent sandbox exposes an unauthenticated TCP command server"
}
func (autoAgentUnauthTCPCommandServer) Severity() finding.Severity {
	return finding.SeverityCritical
}
func (autoAgentUnauthTCPCommandServer) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (autoAgentUnauthTCPCommandServer) Formats() []parse.Format {
	return []parse.Format{parse.FormatAutoAgentSource}
}

func (autoAgentUnauthTCPCommandServer) Apply(doc *parse.Document) []finding.Finding {
	if doc.Format != parse.FormatAutoAgentSource {
		return nil
	}

	// Normalize insignificant Python whitespace while retaining punctuation so
	// this remains a narrow match for the published AutoAgent implementation.
	executable := autoAgentExecutablePython(doc.Raw)
	lower := strings.ToLower(executable)
	compact := strings.NewReplacer(" ", "", "	", "", "\r", "", "\n", "").Replace(lower)
	markers := []string{
		"socket.socket(socket.af_inet,socket.sock_stream)",
		"server.bind((\"0.0.0.0\",args.port))",
		"server.listen(1)",
		"server.accept()",
		"command=receive_all(conn)",
		"/bin/bash-c",
		"{command}",
		"subprocess.popen(modified_command,shell=true",
	}
	for _, marker := range markers {
		if !strings.Contains(compact, marker) {
			return nil
		}
	}

	return []finding.Finding{finding.New(finding.Args{
		RuleID:       "autoagent-unauth-tcp-command-server",
		Severity:     finding.SeverityCritical,
		Taxonomy:     finding.TaxDetectable,
		Title:        "AutoAgent sandbox exposes an unauthenticated TCP command server",
		Description:  "CVE-2026-86124: AutoAgent's sandbox TCP server binds to every interface, accepts commands without authentication, and executes received input through a shell. The published container wiring runs this server as root, publishes its port, and bind-mounts the host workspace.",
		Path:         doc.Path,
		Line:         findLineContaining([]byte(executable), "server.bind"),
		Match:        "all-interface TCP input reaches shell execution",
		SuggestedFix: "Remove or disable AutoAgent's sandbox TCP command server until an authenticated fixed release is available. Do not publish its communication port; bind only to a protected local interface, run the container as a non-root user, and avoid mounting sensitive host workspaces.",
		Tags:         []string{"cve", "autoagent", "tcp-server", "missing-authentication", "command-execution", "container", "cwe-306"},
	})}
}

// autoAgentExecutablePython blanks Python comments and triple-quoted string
// contents before marker matching. It preserves source line numbers and
// executable single-line f-string contents used by the published data flow.
func autoAgentExecutablePython(raw []byte) string {
	var out []string
	var triple string
	for _, line := range strings.Split(string(raw), "\n") {
		if triple != "" {
			end := strings.Index(line, triple)
			if end < 0 {
				out = append(out, "")
				continue
			}
			line = line[end+len(triple):]
			triple = ""
		}
		line = stripPythonInlineComment(line)

		for {
			quote, start := firstPythonTripleQuote(line)
			if start < 0 {
				break
			}
			rest := line[start+len(quote):]
			end := strings.Index(rest, quote)
			if end < 0 {
				line = line[:start]
				triple = quote
				break
			}
			line = line[:start] + rest[end+len(quote):]
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func firstPythonTripleQuote(line string) (string, int) {
	double := strings.Index(line, `"""`)
	single := strings.Index(line, `'''`)
	switch {
	case double < 0:
		return `'''`, single
	case single < 0 || double < single:
		return `"""`, double
	default:
		return `'''`, single
	}
}

func stripPythonInlineComment(line string) string {
	var quote byte
	escaped := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '#':
			return line[:i]
		}
	}
	return line
}
