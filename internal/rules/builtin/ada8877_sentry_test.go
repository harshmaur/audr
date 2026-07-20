package builtin

import (
	"strings"
	"testing"

	"github.com/harshmaur/audr/internal/parse"
	"github.com/harshmaur/audr/internal/rules"
)

const ada8877SentryPayloadFixture = `
const Sentry = require("@sentry/node");
Sentry.init({
  dsn: "https://example@o4510485815754752.ingest.us.sentry.io/4511744089718784",
  sendDefaultPii: true,
});
fetch("https://www.cloudflare.com/cdn-cgi/trace");
`

func TestRule_Ada8877PackageMetadataIOC(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		raw     string
		wantHit bool
	}{
		{
			name:    "syft lookalike package",
			path:    "/repo/node_modules/syft-acp-atoms/package.json",
			raw:     `{"name":"syft-acp-atoms","version":"1.0.0","scripts":{"preinstall":"npm install @sentry/node && node examples/verify.js"}}`,
			wantHit: true,
		},
		{
			name:    "edgecommons scoped package",
			path:    "/repo/node_modules/@edgecommons/streamlog-node/package.json",
			raw:     `{"name":"@edgecommons/streamlog-node","version":"1.0.0","scripts":{"preinstall":"npm install @sentry/node && node examples/verify.js"}}`,
			wantHit: true,
		},
		{
			name:    "same hook outside campaign packages",
			path:    "/repo/node_modules/example/package.json",
			raw:     `{"name":"example","version":"1.0.0","scripts":{"preinstall":"npm install @sentry/node && node examples/verify.js"}}`,
			wantHit: false,
		},
		{
			name:    "campaign package without hook",
			path:    "/repo/node_modules/syft-acp-core/package.json",
			raw:     `{"name":"syft-acp-core","version":"1.0.0"}`,
			wantHit: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := parse.Parse(tc.path, []byte(tc.raw))
			got := fired(doc, "ada8877-sentry-dependency-confusion-ioc")
			if got != tc.wantHit {
				t.Fatalf("fired = %v, want %v; format=%q findings=%v", got, tc.wantHit, doc.Format, applyRule(doc))
			}
		})
	}
}

func TestRule_Ada8877VerifyPayloadIOC(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		raw     string
		wantHit bool
	}{
		{
			name:    "syft payload",
			path:    "/repo/node_modules/syft-acp-uikit/examples/verify.js",
			raw:     ada8877SentryPayloadFixture,
			wantHit: true,
		},
		{
			name:    "edgecommons payload",
			path:    "/repo/node_modules/@edgecommons/edgecommons/examples/verify.js",
			raw:     ada8877SentryPayloadFixture,
			wantHit: true,
		},
		{
			name:    "pnpm payload",
			path:    "/repo/node_modules/.pnpm/@edgecommons+edgecommons@1.0.0/node_modules/@edgecommons/edgecommons/examples/verify.js",
			raw:     ada8877SentryPayloadFixture,
			wantHit: true,
		},
		{
			name:    "same markers outside campaign package roots",
			path:    "/repo/node_modules/example/examples/verify.js",
			raw:     ada8877SentryPayloadFixture,
			wantHit: false,
		},
		{
			name:    "incomplete marker combination",
			path:    "/repo/node_modules/syft-acp-atoms/examples/verify.js",
			raw:     `Sentry.init({sendDefaultPii: true});`,
			wantHit: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := parse.Parse(tc.path, []byte(tc.raw))
			got := fired(doc, "ada8877-sentry-dependency-confusion-ioc")
			if got != tc.wantHit {
				t.Fatalf("fired = %v, want %v; format=%q findings=%v", got, tc.wantHit, doc.Format, applyRule(doc))
			}
		})
	}
}

func TestRule_Ada8877FindingRedactsPayloadContent(t *testing.T) {
	raw := ada8877SentryPayloadFixture + `const token = "ghp_example_secret";`
	doc := parse.Parse("/repo/node_modules/syft-acp-core/examples/verify.js", []byte(raw))
	for _, rule := range rules.All() {
		if rule.ID() != "ada8877-sentry-dependency-confusion-ioc" {
			continue
		}
		for _, result := range rule.Apply(doc) {
			if strings.Contains(result.Match, "ghp_example_secret") || strings.Contains(result.Description, "ghp_example_secret") {
				t.Fatalf("finding leaked payload content: %+v", result)
			}
			return
		}
	}
	t.Fatal("expected ada8877-sentry-dependency-confusion-ioc finding")
}
