package builtin

import (
	"strings"
	"testing"

	"github.com/harshmaur/audr/internal/parse"
	"github.com/harshmaur/audr/internal/rules"
)

func TestRule_AsyncAPIMiasmaDroppedPayloadPaths(t *testing.T) {
	paths := []string{
		"/home/alice/.local/share/NodeJS/sync.js",
		"/Users/alice/Library/Application Support/NodeJS/sync.js",
		`C:\Users\alice\AppData\Local\NodeJS\sync.js`,
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			doc := parse.Parse(path, []byte(`/* recovered payload */`))
			if !fired(doc, "asyncapi-miasma-rat-ioc") {
				t.Fatalf("AsyncAPI Miasma drop-path rule did not fire for %s; format=%q findings=%v", path, doc.Format, applyRule(doc))
			}
		})
	}
}

func TestRule_AsyncAPIMiasmaPackagePayloadMarkers(t *testing.T) {
	tests := []struct {
		path   string
		marker string
	}{
		{"/repo/node_modules/@asyncapi/generator/lib/templates/config/validator.js", "QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9"},
		{"/repo/node_modules/@asyncapi/generator-helpers/src/utils.js", "miasma-train-p1"},
		{"/repo/node_modules/@asyncapi/generator-components/src/utils/ErrorHandling.js", "rt-vault-master-key-32b-aaaaaaaa"},
		{"/repo/node_modules/@asyncapi/specs/index.js", "Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf"},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			doc := parse.Parse(tc.path, []byte("const marker = "+tc.marker+";"))
			if !fired(doc, "asyncapi-miasma-rat-ioc") {
				t.Fatalf("AsyncAPI Miasma package IOC rule did not fire for %s; format=%q findings=%v", tc.path, doc.Format, applyRule(doc))
			}
		})
	}
}

func TestRule_AsyncAPIMiasmaBoundsFalsePositives(t *testing.T) {
	tests := []struct {
		path string
		raw  string
	}{
		{"/repo/README.md", "Threat report: miasma-train-p1 QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9"},
		{"/repo/node_modules/@other/pkg/index.js", "const marker = 'miasma-train-p1';"},
		{"/repo/node_modules/@asyncapi/specs/index.js", "module.exports = {version: 'clean'};"},
		{"/repo/NodeJS/sync.js", "/* unrelated local sync helper */"},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			doc := parse.Parse(tc.path, []byte(tc.raw))
			if fired(doc, "asyncapi-miasma-rat-ioc") {
				t.Fatalf("AsyncAPI Miasma rule fired outside bounded evidence for %s: %v", tc.path, applyRule(doc))
			}
		})
	}
}

func TestRule_AsyncAPIMiasmaFindingRedactsPayloadContent(t *testing.T) {
	doc := parse.Parse("/repo/node_modules/@asyncapi/specs/index.js", []byte(`const token = "ghp_example_secret"; const marker = "miasma-train-p1";`))
	for _, rule := range rules.All() {
		if rule.ID() != "asyncapi-miasma-rat-ioc" {
			continue
		}
		for _, result := range rule.Apply(doc) {
			if strings.Contains(result.Match, "ghp_example_secret") || strings.Contains(result.Description, "ghp_example_secret") {
				t.Fatalf("finding leaked payload content: %+v", result)
			}
			return
		}
	}
	t.Fatal("expected asyncapi-miasma-rat-ioc finding")
}
