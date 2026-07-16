package builtin

import (
	"testing"

	"github.com/harshmaur/audr/internal/parse"
)

func TestMCPPythonSDKWebSocketOriginValidation(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		raw     string
		wantHit bool
	}{
		{
			name:    "vulnerable requirements dependency",
			path:    "requirements.txt",
			raw:     "mcp==1.27.1\n",
			wantHit: true,
		},
		{
			name:    "vulnerable pyproject dependency",
			path:    "pyproject.toml",
			raw:     "[project]\nname = \"agent-server\"\nversion = \"1.0.0\"\ndependencies = [\"mcp>=1.20.0,<1.28.1\"]\n",
			wantHit: true,
		},
		{
			name:    "fixed requirements dependency",
			path:    "requirements.txt",
			raw:     "mcp==1.28.1\n",
			wantHit: false,
		},
		{
			name:    "unrelated npm package",
			path:    "package.json",
			raw:     `{"name":"workspace","version":"1.0.0","dependencies":{"mcp":"1.27.1"}}`,
			wantHit: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := parse.Parse(tc.path, []byte(tc.raw))
			findings := (mcpPythonSDKWebSocketOriginValidation{}).Apply(doc)
			if tc.wantHit && len(findings) != 1 {
				t.Fatalf("got %d findings, want 1", len(findings))
			}
			if !tc.wantHit && len(findings) != 0 {
				t.Fatalf("got %d findings, want 0", len(findings))
			}
			if tc.wantHit && findings[0].RuleID != "mcp-python-sdk-websocket-origin-validation" {
				t.Fatalf("rule id = %q", findings[0].RuleID)
			}
		})
	}
}
