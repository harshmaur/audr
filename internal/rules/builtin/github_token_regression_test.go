package builtin

import (
	"strings"
	"testing"
)

func TestMatchesCredentialFineGrainedGitHubToken(t *testing.T) {
	token := "github_pat_" + strings.Repeat("a", 22) + "_" + strings.Repeat("b", 59)
	if !matchesCredential("", token) {
		t.Fatal("fine-grained GitHub token not recognized by value")
	}
	if matchesCredential("", "github_pat_short") {
		t.Fatal("short non-token matched")
	}
}
