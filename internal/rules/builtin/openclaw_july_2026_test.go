package builtin

import (
	"testing"

	"github.com/harshmaur/audr/internal/parse"
)

func TestOpenClawHostExecGitExtTransportFiltering(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		raw     string
		wantHit bool
	}{
		{
			name:    "vulnerable direct package",
			path:    "package.json",
			raw:     `{"name":"agent-workspace","version":"1.0.0","dependencies":{"openclaw":"2026.5.31"}}`,
			wantHit: true,
		},
		{
			name:    "vulnerable dev dependency",
			path:    "package.json",
			raw:     `{"name":"agent-workspace","version":"1.0.0","devDependencies":{"openclaw":"^2026.6.5"}}`,
			wantHit: true,
		},
		{
			name:    "fixed package",
			path:    "package.json",
			raw:     `{"name":"agent-workspace","version":"1.0.0","dependencies":{"openclaw":"2026.6.6"}}`,
			wantHit: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := parse.Parse(tc.path, []byte(tc.raw))
			findings := (openclawHostExecGitExtTransportFiltering{}).Apply(doc)
			if tc.wantHit && len(findings) != 1 {
				t.Fatalf("got %d findings, want 1", len(findings))
			}
			if !tc.wantHit && len(findings) != 0 {
				t.Fatalf("got %d findings, want 0", len(findings))
			}
			if tc.wantHit && findings[0].RuleID != "openclaw-host-exec-git-ext-transport-filtering" {
				t.Fatalf("rule id = %q", findings[0].RuleID)
			}
		})
	}
}
