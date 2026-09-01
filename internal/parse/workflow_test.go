package parse

import "testing"

func TestParseWorkflowCapturesJobAndStepConditions(t *testing.T) {
	raw := []byte(`name: Release
on: [issue_comment]
jobs:
  release:
    if: github.event_name == 'issue_comment'
    runs-on: ubuntu-latest
    steps:
      - name: Publish
        if: github.event.comment.body == 'npm publish'
        run: npm publish
`)
	doc := Parse("/repo/.github/workflows/release.yml", raw)
	if doc.Workflow == nil {
		t.Fatal("workflow was not parsed")
	}
	if !doc.Workflow.Triggers["issue_comment"] {
		t.Fatalf("workflow triggers = %+v", doc.Workflow.Triggers)
	}
	job, ok := doc.Workflow.Jobs["release"]
	if !ok {
		t.Fatal("release job missing")
	}
	if job.If != "github.event_name == 'issue_comment'" {
		t.Fatalf("job if = %q", job.If)
	}
	if len(job.Steps) != 1 || job.Steps[0].If != "github.event.comment.body == 'npm publish'" {
		t.Fatalf("step conditions not parsed: %+v", job.Steps)
	}
}

func TestParseWorkflowCapturesBlockListTriggers(t *testing.T) {
	doc := Parse("/repo/.github/workflows/release.yml", []byte(`on:
  - push
  - issue_comment
jobs: {}
`))
	if doc.Workflow == nil || !doc.Workflow.Triggers["push"] || !doc.Workflow.Triggers["issue_comment"] {
		t.Fatalf("workflow triggers = %+v", doc.Workflow)
	}
}
