package builtin

import (
	"testing"

	"github.com/harshmaur/audr/internal/parse"
)

func TestRule_MiseHTTPBackendSymlinkEscape(t *testing.T) {
	doc := parse.Parse("/repo/.tool-versions", []byte("node https://tools.example/node.tar.gz?bin_path=/tmp/pwn/bin\n"))
	if doc.Format != parse.FormatMiseToolVersions {
		t.Fatalf("format = %q, want %q", doc.Format, parse.FormatMiseToolVersions)
	}
	findings := (miseHTTPBackendSymlinkEscape{}).Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1; rules fired: %v", len(findings), applyRule(doc))
	}
	if findings[0].Line != 1 {
		t.Fatalf("line = %d, want 1", findings[0].Line)
	}
}

func TestRule_MiseHTTPBackendSymlinkEscapeAbsoluteVersion(t *testing.T) {
	doc := parse.Parse("/repo/.tool-versions", []byte("python http://tools.example/python.tgz /opt/attacker-prefix\n"))
	if !fired(doc, "mise-http-backend-symlink-escape") {
		t.Fatalf("expected absolute HTTP backend version target to fire; rules fired: %v", applyRule(doc))
	}
}

func TestRule_MiseHTTPBackendSymlinkEscapeBenignHTTPBackend(t *testing.T) {
	doc := parse.Parse("/repo/.tool-versions", []byte("node https://tools.example/node.tar.gz?bin_path=bin\npython 3.12.4\n"))
	if fired(doc, "mise-http-backend-symlink-escape") {
		t.Fatalf("did not expect relative HTTP backend config to fire; rules fired: %v", applyRule(doc))
	}
}
