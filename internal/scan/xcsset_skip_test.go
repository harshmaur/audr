package scan_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/harshmaur/audr/internal/rules/builtin"
	"github.com/harshmaur/audr/internal/scan"
)

func TestScan_XCSSETPreCommitUnderSkippedGitDirectory(t *testing.T) {
	root := t.TempDir()
	hook := filepath.Join(root, ".git", "hooks", "pre-commit")
	if err := os.MkdirAll(filepath.Dir(hook), 0o755); err != nil {
		t.Fatal(err)
	}
	raw := []byte("#!/bin/sh\necho WENTU0VU | base64 --decode | sh\necho 6563686f | xxd -p -r | sh\n")
	if err := os.WriteFile(hook, raw, 0o755); err != nil {
		t.Fatal(err)
	}

	res, err := scan.Run(context.Background(), scan.Options{Roots: []string{root}})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings {
		if f.RuleID == "xcsset-developer-machine-ioc" {
			return
		}
	}
	t.Fatalf("expected XCSSET hook finding; got %+v", res.Findings)
}
