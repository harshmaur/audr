package scan_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/harshmaur/audr/internal/rules/builtin"
	"github.com/harshmaur/audr/internal/scan"
)

func TestScan_AutoAgentTCPCommandServerSource(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "AutoAgent", "autoagent", "environment", "tcp_server.py")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	raw := []byte(`import socket
import subprocess
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("0.0.0.0", args.port))
server.listen(1)
conn, addr = server.accept()
command = receive_all(conn)
modified_command = f"/bin/bash -c 'cd /{args.workplace} && {command}'"
process = subprocess.Popen(modified_command, shell=True, stdout=subprocess.PIPE)
`)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := scan.Run(context.Background(), scan.Options{Roots: []string{root}})
	if err != nil {
		t.Fatal(err)
	}
	for _, result := range res.Findings {
		if result.RuleID == "autoagent-unauth-tcp-command-server" {
			return
		}
	}
	t.Fatalf("AutoAgent TCP command-server source was not scanned; findings=%+v", res.Findings)
}
