package builtin

import (
	"testing"

	"github.com/harshmaur/audr/internal/parse"
)

func TestSiYuanConfigFormatDetection(t *testing.T) {
	for _, path := range []string{
		"/home/user/.siyuan/conf.json",
		"/workspace/conf/conf.json",
		`C:\\Users\\user\\.siyuan\\conf.json`,
	} {
		if got := parse.DetectFormat(path); got != parse.Format("siyuan-config") {
			t.Fatalf("DetectFormat(%q) = %q, want siyuan-config", path, got)
		}
	}
	if got := parse.DetectFormat("/repo/conf.json"); got != parse.FormatUnknown {
		t.Fatalf("unscoped conf.json format = %q, want unknown", got)
	}
}

func TestSiYuanAnonymousPublishMCPVulnerablePosture(t *testing.T) {
	doc := parse.Parse("/home/user/.siyuan/conf.json", []byte(`{
		"system": {"kernelVersion": "3.7.1"},
		"publish": {"enable": true, "auth": {"enable": false}}
	}`))
	if !fired(doc, "siyuan-anonymous-publish-mcp-admin-bypass") {
		t.Fatalf("expected SiYuan anonymous Publish finding; rules fired: %v", applyRule(doc))
	}
}

func TestSiYuanAuthenticatedPublishDoesNotFire(t *testing.T) {
	doc := parse.Parse("/home/user/.siyuan/conf.json", []byte(`{
		"system": {"kernelVersion": "3.7.1"},
		"publish": {"enable": true, "auth": {"enable": true}}
	}`))
	if fired(doc, "siyuan-anonymous-publish-mcp-admin-bypass") {
		t.Fatalf("authenticated Publish should be clean; rules fired: %v", applyRule(doc))
	}
}

func TestSiYuanFixedVersionDoesNotFire(t *testing.T) {
	doc := parse.Parse("/workspace/conf/conf.json", []byte(`{
		"system": {"kernelVersion": "3.7.2"},
		"publish": {"enable": true, "auth": {"enable": false}}
	}`))
	if fired(doc, "siyuan-anonymous-publish-mcp-admin-bypass") {
		t.Fatalf("fixed SiYuan version should be clean; rules fired: %v", applyRule(doc))
	}
}

func TestSiYuanDisabledPublishDoesNotFire(t *testing.T) {
	doc := parse.Parse("/home/user/.siyuan/conf.json", []byte(`{
		"system": {"kernelVersion": "3.7.1"},
		"publish": {"enable": false, "auth": {"enable": false}}
	}`))
	if fired(doc, "siyuan-anonymous-publish-mcp-admin-bypass") {
		t.Fatalf("disabled Publish should be clean; rules fired: %v", applyRule(doc))
	}
}
