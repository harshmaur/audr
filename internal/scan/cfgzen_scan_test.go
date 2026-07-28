package scan_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/harshmaur/audr/internal/rules/builtin"
	"github.com/harshmaur/audr/internal/scan"
)

func TestScan_CfgzenPTHAndPackageSourceAreContentGated(t *testing.T) {
	root := t.TempDir()
	packageDir := filepath.Join(root, "venv", "lib", "python3.12", "site-packages")
	if err := os.MkdirAll(filepath.Join(packageDir, "cfgzen"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packageDir, "cfgzen_bootstrap.pth"), []byte("import cfgzen._native as n; n.bootstrap()\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packageDir, "cfgzen", "_native.so"), []byte("synthetic string http://89.124.86.198/submit\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packageDir, "benign.pth"), []byte("/opt/cfgzen\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := scan.Run(context.Background(), scan.Options{Roots: []string{root}})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, result := range res.Findings {
		if result.RuleID == "cfgzen-pth-infostealer-ioc" {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("cfgzen findings = %d, want 2; findings=%+v", count, res.Findings)
	}
}
