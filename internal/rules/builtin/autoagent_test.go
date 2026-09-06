package builtin

import (
	"strings"
	"testing"

	"github.com/harshmaur/audr/internal/parse"
	"github.com/harshmaur/audr/internal/rules"
)

func TestAutoAgentTCPCommandServerDetectsVulnerableSource(t *testing.T) {
	raw := []byte(`# """ commented documentation delimiter must not hide code
import socket
import subprocess
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("0.0.0.0", args.port))
server.listen(1)
conn, addr = server.accept()
command = receive_all(conn)
modified_command = f"/bin/bash -c 'cd /{args.workplace} && {command}'"
process = subprocess.Popen(modified_command, shell=True, stdout=subprocess.PIPE)
`)
	doc := parse.Parse("/repo/AutoAgent/autoagent/environment/tcp_server.py", raw)
	if doc.Format != parse.FormatAutoAgentSource {
		t.Fatalf("format = %q, want %q", doc.Format, parse.FormatAutoAgentSource)
	}
	if !fired(doc, "autoagent-unauth-tcp-command-server") {
		t.Fatalf("expected AutoAgent TCP command-server rule to fire; rules fired: %v", applyRule(doc))
	}
}

func TestAutoAgentTCPCommandServerRequiresBoundedPathAndFullDataFlow(t *testing.T) {
	vulnerable := `import socket
import subprocess
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("0.0.0.0", args.port))
server.listen(1)
conn, addr = server.accept()
command = receive_all(conn)
modified_command = f"/bin/bash -c '{command}'"
process = subprocess.Popen(modified_command, shell=True)
`
	tests := []struct {
		name string
		path string
		raw  string
	}{
		{"unrelated filename", "/repo/src/server_example.py", vulnerable},
		{"loopback bind", "/repo/AutoAgent/autoagent/environment/tcp_server.py", strings.Replace(vulnerable, `"0.0.0.0"`, `"127.0.0.1"`, 1)},
		{"no received command", "/repo/AutoAgent/autoagent/environment/tcp_server.py", strings.Replace(vulnerable, "command = receive_all(conn)\n", "command = trusted_command\n", 1)},
		{"no shell execution", "/repo/AutoAgent/autoagent/environment/tcp_server.py", strings.Replace(vulnerable, "shell=True", "shell=False", 1)},
		{"commented out block", "/repo/AutoAgent/autoagent/environment/tcp_server.py", "# " + strings.ReplaceAll(vulnerable, "\n", "\n# ")},
		{"docstring only", "/repo/AutoAgent/autoagent/environment/tcp_server.py", "\"\"\"\n" + vulnerable + "\"\"\"\n"},
		{"raw docstring only", "/repo/AutoAgent/autoagent/environment/tcp_server.py", "r\"\"\"\n" + vulnerable + "\"\"\"\n"},
		{"assigned docstring only", "/repo/AutoAgent/autoagent/environment/tcp_server.py", "documentation = \"\"\"\n" + vulnerable + "\"\"\"\n"},
		{"markers only in inline comments", "/repo/AutoAgent/autoagent/environment/tcp_server.py", strings.Replace(strings.Replace(vulnerable, "command = receive_all(conn)", "command = trusted_command  # command = receive_all(conn)", 1), "subprocess.Popen(modified_command, shell=True)", "subprocess.Popen(modified_command, shell=False)  # subprocess.Popen(modified_command, shell=True)", 1)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := parse.Parse(tc.path, []byte(tc.raw))
			if fired(doc, "autoagent-unauth-tcp-command-server") {
				t.Fatalf("did not expect AutoAgent rule for %s; rules fired: %v", tc.path, applyRule(doc))
			}
		})
	}
}

func TestAutoAgentTCPCommandServerRoutesCopiedAndWindowsPaths(t *testing.T) {
	windowsPath := strings.Join([]string{"C:", "Users", "alice", "workspace", "tcp_server.py"}, string(rune(92)))
	for _, path := range []string{
		"/workspace/tcp_server.py",
		"/home/alice/docs/AutoAgent/autoagent/environment/tcp_server.py",
		windowsPath,
	} {
		if got := parse.DetectFormat(path); got != parse.FormatAutoAgentSource {
			t.Fatalf("DetectFormat(%q) = %q, want %q", path, got, parse.FormatAutoAgentSource)
		}
	}
}

func TestAutoAgentTCPCommandServerFindingIsRegisteredAndRedacted(t *testing.T) {
	doc := parse.Parse("/repo/AutoAgent/autoagent/environment/tcp_server.py", []byte(`# server.bind(("0.0.0.0", args.port))
import socket
import subprocess
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("0.0.0.0", args.port))
server.listen(1)
conn, addr = server.accept()
command = receive_all(conn)
modified_command = f"/bin/bash -c '{command}'"
process = subprocess.Popen(modified_command, shell=True)
`))
	for _, rule := range rules.All() {
		if rule.ID() != "autoagent-unauth-tcp-command-server" {
			continue
		}
		findings := rule.Apply(doc)
		if len(findings) != 1 {
			t.Fatalf("got %d findings, want 1", len(findings))
		}
		if !strings.Contains(findings[0].Description, "CVE-2026-86124") {
			t.Fatalf("description does not name CVE-2026-86124: %q", findings[0].Description)
		}
		if strings.Contains(findings[0].Match, "{command}") || strings.Contains(findings[0].Match, "/bin/bash -c") {
			t.Fatalf("finding Match echoes executable source: %q", findings[0].Match)
		}
		if findings[0].Line != 5 {
			t.Fatalf("finding line = %d, want executable bind on line 5", findings[0].Line)
		}
		return
	}
	t.Fatal("autoagent-unauth-tcp-command-server rule is not registered")
}
