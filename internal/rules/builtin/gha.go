// Rules over GitHub Actions workflow files (.github/workflows/*.yml).
package builtin

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

// --- gha-write-all-permissions --------------------------------------------

type ghaWriteAllPermissions struct{}

func (ghaWriteAllPermissions) ID() string { return "gha-write-all-permissions" }
func (ghaWriteAllPermissions) Title() string {
	return "GitHub Actions job grants write-all permissions"
}
func (ghaWriteAllPermissions) Severity() finding.Severity { return finding.SeverityHigh }
func (ghaWriteAllPermissions) Taxonomy() finding.Taxonomy { return finding.TaxEnforced }
func (ghaWriteAllPermissions) Formats() []parse.Format {
	return []parse.Format{parse.FormatGHAWorkflow}
}

func (ghaWriteAllPermissions) Apply(doc *parse.Document) []finding.Finding {
	if doc.Workflow == nil {
		return nil
	}
	var out []finding.Finding
	check := func(scope string, perms map[string]string) {
		if perms == nil {
			return
		}
		// "permissions: write-all" comes through stringMap as {"_": "write-all"}.
		if perms["_"] == "write-all" {
			out = append(out, finding.New(finding.Args{
				RuleID:       "gha-write-all-permissions",
				Severity:     finding.SeverityHigh,
				Taxonomy:     finding.TaxEnforced,
				Title:        fmt.Sprintf("Workflow grants write-all permissions (%s)", scope),
				Description:  fmt.Sprintf("`permissions: write-all` at %s grants the GITHUB_TOKEN maximum scope for the duration of the run. A compromised step has full repo write + secret read.", scope),
				Path:         doc.Path,
				Match:        "permissions: write-all",
				SuggestedFix: "Replace with the minimum required scopes (e.g. `permissions: { contents: read, pull-requests: write }`).",
				Tags:         []string{"gha", "least-privilege"},
			}))
		}
	}
	check("workflow level", doc.Workflow.Permissions)
	for jobName, j := range doc.Workflow.Jobs {
		check("job "+jobName, j.Permissions)
	}
	return out
}

// --- gha-secrets-in-agent-step --------------------------------------------

type ghaSecretsInAgentStep struct{}

func (ghaSecretsInAgentStep) ID() string                 { return "gha-secrets-in-agent-step" }
func (ghaSecretsInAgentStep) Title() string              { return "GHA step exposes secrets to an agent invocation" }
func (ghaSecretsInAgentStep) Severity() finding.Severity { return finding.SeverityHigh }
func (ghaSecretsInAgentStep) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (ghaSecretsInAgentStep) Formats() []parse.Format    { return []parse.Format{parse.FormatGHAWorkflow} }

var agentInvocationPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\b(claude|cursor|aider|cody|codex|crush|hermes|continue)\b`),
	regexp.MustCompile(`anthropics?/claude`),
	regexp.MustCompile(`anthropic-ai/`),
}

func (ghaSecretsInAgentStep) Apply(doc *parse.Document) []finding.Finding {
	if doc.Workflow == nil {
		return nil
	}
	var out []finding.Finding
	for jobName, job := range doc.Workflow.Jobs {
		for _, step := range job.Steps {
			invokesAgent := false
			lower := strings.ToLower(step.Name + " " + step.Uses + " " + step.Run)
			for _, pat := range agentInvocationPatterns {
				if pat.MatchString(lower) {
					invokesAgent = true
					break
				}
			}
			if !invokesAgent {
				continue
			}
			// Look for secrets.* references in env.
			for k, v := range step.Env {
				if !strings.Contains(v, "secrets.") {
					continue
				}
				out = append(out, finding.New(finding.Args{
					RuleID:       "gha-secrets-in-agent-step",
					Severity:     finding.SeverityHigh,
					Taxonomy:     finding.TaxDetectable,
					Title:        "Secret passed to step that invokes an AI coding agent",
					Description:  fmt.Sprintf("Step in job %q invokes an agent (%s) and exposes %s via env. Agents with shell access plus secret access are a single misconfiguration away from leaking credentials.", jobName, strings.TrimSpace(step.Name+" "+step.Uses), k),
					Path:         doc.Path,
					Match:        fmt.Sprintf("%s: %s", k, v),
					SuggestedFix: "Pass only the minimal credential the agent needs, scoped to the operation. Avoid generic `GITHUB_TOKEN` exposure to autonomous code-changing agents.",
					Tags:         []string{"gha", "agent", "secrets"},
				}))
			}
		}
	}
	return out
}

// --- gha-base64-secret-exfil-workflow --------------------------------------

type ghaBase64SecretExfilWorkflow struct{}

func (ghaBase64SecretExfilWorkflow) ID() string {
	return "gha-base64-secret-exfil-workflow"
}
func (ghaBase64SecretExfilWorkflow) Title() string {
	return "GitHub Actions workflow decodes and runs a secret-exfiltration payload"
}
func (ghaBase64SecretExfilWorkflow) Severity() finding.Severity { return finding.SeverityCritical }
func (ghaBase64SecretExfilWorkflow) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (ghaBase64SecretExfilWorkflow) Formats() []parse.Format {
	return []parse.Format{parse.FormatGHAWorkflow}
}

var ghaBase64DecodeExecutePattern = regexp.MustCompile(`(?is)(base64\s+(?:-d|--decode)[^\n|;]*\|\s*(?:bash|sh)\b|echo\s+['\"][a-z0-9+/=]{80,}['\"]\s*\|\s*base64\s+(?:-d|--decode)\s*\|\s*(?:bash|sh)\b)`)

func (ghaBase64SecretExfilWorkflow) Apply(doc *parse.Document) []finding.Finding {
	if doc.Workflow == nil {
		return nil
	}
	raw := string(doc.Raw)
	lower := strings.ToLower(raw)
	if !ghaBase64DecodeExecutePattern.MatchString(raw) {
		return nil
	}

	exfilSignals := 0
	for _, needle := range []string{
		"216.126.225.129:8443",
		"actions_id_token_request_url",
		"actions_id_token_request_token",
		"github_token",
		"/proc/1/environ",
		"/proc/*/environ",
		"aws_access_key_id",
		"aws_secret_access_key",
		"gcloud auth print-access-token",
		"169.254.169.254",
		"metadata.google.internal",
		".docker/config.json",
		".npmrc",
		".netrc",
		"id_rsa",
		"kube/config",
		"terraform.d/credentials",
		"credentials.json",
		"service-account.json",
		"curl -x post",
		"curl -xpost",
		"curl -d",
		"curl --data",
		"curl --request post",
	} {
		if strings.Contains(lower, needle) {
			exfilSignals++
		}
	}

	campaignShape := strings.EqualFold(doc.Workflow.Name, "SysDiag") || strings.EqualFold(doc.Workflow.Name, "Optimize-Build") || strings.Contains(lower, "name: sysdiag") || strings.Contains(lower, "name: optimize-build") || strings.Contains(lower, "workflow_dispatch") || strings.Contains(lower, "pull_request_target")
	if !(strings.Contains(lower, "216.126.225.129:8443") || exfilSignals >= 2 || campaignShape && exfilSignals >= 1) {
		return nil
	}

	return []finding.Finding{finding.New(finding.Args{
		RuleID:       "gha-base64-secret-exfil-workflow",
		Severity:     finding.SeverityCritical,
		Taxonomy:     finding.TaxDetectable,
		Title:        "Workflow decodes and executes a CI secret exfiltration payload",
		Description:  "This GitHub Actions workflow decodes a base64 shell payload and includes CI/cloud credential exfiltration signals. This matches the Megalodon mass repository backdooring pattern and similar workflow malware.",
		Path:         doc.Path,
		Line:         findLineContaining(doc.Raw, "base64"),
		Match:        "base64 decode-and-execute workflow with CI/cloud secret exfiltration signals",
		SuggestedFix: "Remove the workflow or malicious step, inspect recent Actions runs, rotate GitHub/cloud/registry/SSH credentials exposed to CI, audit commit provenance, and require review for workflow changes.",
		Tags:         []string{"gha", "workflow", "base64", "secrets", "exfiltration", "malware", "megalodon"},
	})}
}

// --- gha-claude-issue-agent-injection --------------------------------------

type ghaClaudeIssueAgentInjection struct{}

func (ghaClaudeIssueAgentInjection) ID() string { return "gha-claude-issue-agent-injection" }
func (ghaClaudeIssueAgentInjection) Title() string {
	return "Issue-triggered Claude workflow embeds untrusted issue content"
}
func (ghaClaudeIssueAgentInjection) Severity() finding.Severity { return finding.SeverityHigh }
func (ghaClaudeIssueAgentInjection) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (ghaClaudeIssueAgentInjection) Formats() []parse.Format {
	return []parse.Format{parse.FormatGHAWorkflow}
}

func (ghaClaudeIssueAgentInjection) Apply(doc *parse.Document) []finding.Finding {
	if doc.Workflow == nil {
		return nil
	}
	raw := string(doc.Raw)
	lower := strings.ToLower(raw)
	if !(strings.Contains(lower, "anthropics/claude-code-action") || strings.Contains(lower, "anthropic-ai/claude-code-action")) {
		return nil
	}
	if !(strings.Contains(lower, "github.event.issue.title") || strings.Contains(lower, "github.event.issue.body")) {
		return nil
	}
	if !(strings.Contains(lower, "issues:") || strings.Contains(lower, "issue_comment")) {
		return nil
	}

	untrustedIssueTrigger := regexp.MustCompile(`(?is)on\s*:\s*(?:\n|.*)(issues|issue_comment)`).MatchString(raw)
	broadIssueActorAllowance := strings.Contains(lower, "allowed_non_write_users") && strings.Contains(lower, "github.event.issue.user.login")
	if !(untrustedIssueTrigger || broadIssueActorAllowance) {
		return nil
	}

	return []finding.Finding{finding.New(finding.Args{
		RuleID:       "gha-claude-issue-agent-injection",
		Severity:     finding.SeverityHigh,
		Taxonomy:     finding.TaxDetectable,
		Title:        "Claude issue-triage workflow trusts untrusted issue content",
		Description:  "This GitHub Actions workflow runs Claude Code on issue-controlled title/body content and appears reachable from issue events or the issue author. This matches the CVE-2026-44246 agentic workflow injection pattern where an external issue can steer a command-capable agent.",
		Path:         doc.Path,
		Line:         findLineContaining(doc.Raw, "claude-code-action"),
		Match:        "issue-triggered Claude Code workflow with issue title/body prompt input",
		SuggestedFix: "Do not run command-capable agents directly on untrusted issue text. Require maintainer approval, restrict allowed_non_write_users, avoid embedding raw issue title/body in prompts, and minimize GitHub token permissions.",
		Tags:         []string{"gha", "claude", "agentic-workflow", "prompt-injection", "cve", "CVE-2026-44246"},
	})}
}
