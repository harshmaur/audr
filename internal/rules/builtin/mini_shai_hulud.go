package builtin

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

const miniShaiHuludCommit = "79ac49eedf774dd4b0cfa308722bc463cfe5885c"

var miniShaiHuludOptionalDependencies = map[string][]string{
	"@tanstack/setup": {
		"github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c",
	},
	"@antv/setup": {
		"github:antvis/g2#1916faa365f2788b6e193514872d51a242876569",
		"github:antvis/g2#7cb42f57561c",
		"github:antvis/g2#dc3d62a2181b",
	},
}

// --- mini-shai-hulud-malicious-optional-dependency -------------------------

type miniShaiHuludMaliciousOptionalDependency struct{}

func (miniShaiHuludMaliciousOptionalDependency) ID() string {
	return "mini-shai-hulud-malicious-optional-dependency"
}
func (miniShaiHuludMaliciousOptionalDependency) Title() string {
	return "Mini Shai-Hulud malicious optional dependency present"
}
func (miniShaiHuludMaliciousOptionalDependency) Severity() finding.Severity {
	return finding.SeverityCritical
}
func (miniShaiHuludMaliciousOptionalDependency) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (miniShaiHuludMaliciousOptionalDependency) Formats() []parse.Format {
	return []parse.Format{parse.FormatPackageJSON}
}

func (miniShaiHuludMaliciousOptionalDependency) Apply(doc *parse.Document) []finding.Finding {
	if doc.PackageJSON == nil {
		return nil
	}
	for depName, indicators := range miniShaiHuludOptionalDependencies {
		version, ok := doc.PackageJSON.OptionalDependencies[depName]
		if !ok {
			continue
		}
		lower := strings.ToLower(version)
		for _, indicator := range indicators {
			if !strings.Contains(lower, indicator) {
				continue
			}
			return []finding.Finding{finding.New(finding.Args{
				RuleID:       "mini-shai-hulud-malicious-optional-dependency",
				Severity:     finding.SeverityCritical,
				Taxonomy:     finding.TaxDetectable,
				Title:        "Mini Shai-Hulud malicious optional dependency present",
				Description:  "This package.json contains a Mini Shai-Hulud optionalDependency pointing at an attacker-staged GitHub commit. Installing this package can execute the worm payload.",
				Path:         doc.Path,
				Line:         findKeyLineRaw(doc.Raw, depName),
				Match:        depName + " -> " + version,
				SuggestedFix: "Remove the dependency, pin affected packages to known-clean versions, delete node_modules, reinstall from a clean lockfile, and rotate secrets from any environment where install ran.",
				Tags:         []string{"mini-shai-hulud", "npm", "supply-chain", "malware"},
			})}
		}
	}
	return nil
}

// --- mini-shai-hulud-claude-persistence ------------------------------------

type miniShaiHuludClaudePersistence struct{}

func (miniShaiHuludClaudePersistence) ID() string { return "mini-shai-hulud-claude-persistence" }
func (miniShaiHuludClaudePersistence) Title() string {
	return "Mini Shai-Hulud Claude Code persistence hook"
}
func (miniShaiHuludClaudePersistence) Severity() finding.Severity { return finding.SeverityCritical }
func (miniShaiHuludClaudePersistence) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (miniShaiHuludClaudePersistence) Formats() []parse.Format {
	return []parse.Format{parse.FormatClaudeSettings}
}

func (miniShaiHuludClaudePersistence) Apply(doc *parse.Document) []finding.Finding {
	if doc.ClaudeSettings == nil {
		return nil
	}
	raw := strings.ToLower(string(doc.Raw))
	if !strings.Contains(raw, "sessionstart") || !strings.Contains(raw, ".vscode/setup.mjs") {
		return nil
	}
	return []finding.Finding{finding.New(finding.Args{
		RuleID:       "mini-shai-hulud-claude-persistence",
		Severity:     finding.SeverityCritical,
		Taxonomy:     finding.TaxDetectable,
		Title:        "Mini Shai-Hulud Claude Code SessionStart persistence",
		Description:  "Claude Code settings contain a SessionStart hook that launches the Mini Shai-Hulud-style setup payload from .vscode/setup.mjs. This can re-execute malware whenever Claude Code starts a session.",
		Path:         doc.Path,
		Line:         findKeyLineRaw(doc.Raw, "SessionStart"),
		Match:        "SessionStart -> .vscode/setup.mjs",
		SuggestedFix: "Remove the hook and referenced setup payloads, restore Claude settings from a trusted source, isolate the machine, and rotate credentials exposed on the host.",
		Tags:         []string{"mini-shai-hulud", "claude", "persistence", "malware"},
	})}
}

// --- mini-shai-hulud-vscode-persistence ------------------------------------

type miniShaiHuludVSCodePersistence struct{}

func (miniShaiHuludVSCodePersistence) ID() string { return "mini-shai-hulud-vscode-persistence" }
func (miniShaiHuludVSCodePersistence) Title() string {
	return "Mini Shai-Hulud VS Code folder-open persistence task"
}
func (miniShaiHuludVSCodePersistence) Severity() finding.Severity { return finding.SeverityCritical }
func (miniShaiHuludVSCodePersistence) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (miniShaiHuludVSCodePersistence) Formats() []parse.Format {
	return []parse.Format{parse.FormatMiniShaiHuludArtifact}
}

func (miniShaiHuludVSCodePersistence) Apply(doc *parse.Document) []finding.Finding {
	if !isPathSuffix(doc.Path, "/.vscode/tasks.json") {
		return nil
	}
	raw := strings.ToLower(string(doc.Raw))
	if !strings.Contains(raw, "folderopen") || !strings.Contains(raw, ".claude/setup.mjs") {
		return nil
	}
	return []finding.Finding{finding.New(finding.Args{
		RuleID:       "mini-shai-hulud-vscode-persistence",
		Severity:     finding.SeverityCritical,
		Taxonomy:     finding.TaxDetectable,
		Title:        "Mini Shai-Hulud VS Code folder-open persistence task",
		Description:  "VS Code tasks.json contains a runOn=folderOpen task launching a Mini Shai-Hulud-style .claude/setup.mjs payload. Opening the folder can re-execute malware.",
		Path:         doc.Path,
		Line:         findKeyLineRaw(doc.Raw, "folderOpen"),
		Match:        "folderOpen -> .claude/setup.mjs",
		SuggestedFix: "Remove the task and referenced setup payloads, restore VS Code workspace files from a trusted source, isolate the machine, and rotate exposed credentials.",
		Tags:         []string{"mini-shai-hulud", "vscode", "persistence", "malware"},
	})}
}

// --- mini-shai-hulud-token-monitor-persistence -----------------------------

type miniShaiHuludTokenMonitorPersistence struct{}

func (miniShaiHuludTokenMonitorPersistence) ID() string {
	return "mini-shai-hulud-token-monitor-persistence"
}
func (miniShaiHuludTokenMonitorPersistence) Title() string {
	return "Mini Shai-Hulud gh-token-monitor persistence service"
}
func (miniShaiHuludTokenMonitorPersistence) Severity() finding.Severity {
	return finding.SeverityCritical
}
func (miniShaiHuludTokenMonitorPersistence) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (miniShaiHuludTokenMonitorPersistence) Formats() []parse.Format {
	return []parse.Format{parse.FormatMiniShaiHuludArtifact}
}

func (miniShaiHuludTokenMonitorPersistence) Apply(doc *parse.Document) []finding.Finding {
	base := filepath.Base(doc.Path)
	raw := strings.ToLower(string(doc.Raw))
	path := filepath.ToSlash(doc.Path)
	isTokenMonitor := base == "gh-token-monitor.service" || base == "com.user.gh-token-monitor.plist" || strings.Contains(raw, "gh-token-monitor") || strings.HasSuffix(path, "/.local/bin/gh-token-monitor.sh")
	isKittyMonitor := base == "kitty-monitor.service" || base == "com.user.kitty-monitor.plist" || strings.Contains(raw, "kitty-monitor") || strings.Contains(raw, ".local/share/kitty/cat.py")
	if !isTokenMonitor && !isKittyMonitor {
		return nil
	}
	match := "gh-token-monitor"
	lineNeedle := "gh-token-monitor"
	if isKittyMonitor {
		match = "kitty-monitor"
		lineNeedle = "kitty"
	}
	return []finding.Finding{finding.New(finding.Args{
		RuleID:       "mini-shai-hulud-token-monitor-persistence",
		Severity:     finding.SeverityCritical,
		Taxonomy:     finding.TaxDetectable,
		Title:        "Mini Shai-Hulud token monitor persistence service",
		Description:  "This service/LaunchAgent matches Mini Shai-Hulud token-monitor persistence artifacts used to monitor and re-exfiltrate GitHub tokens.",
		Path:         doc.Path,
		Line:         findLineContaining(doc.Raw, lineNeedle),
		Match:        match,
		SuggestedFix: "Stop and disable the service/LaunchAgent, remove the monitor files, isolate the machine, and rotate GitHub/npm/cloud credentials after containment.",
		Tags:         []string{"mini-shai-hulud", "persistence", "github-token", "malware"},
	})}
}

// --- mini-shai-hulud-dropped-payload ---------------------------------------

type miniShaiHuludDroppedPayload struct{}

func (miniShaiHuludDroppedPayload) ID() string { return "mini-shai-hulud-dropped-payload" }
func (miniShaiHuludDroppedPayload) Title() string {
	return "Mini Shai-Hulud dropped payload file present"
}
func (miniShaiHuludDroppedPayload) Severity() finding.Severity { return finding.SeverityCritical }
func (miniShaiHuludDroppedPayload) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (miniShaiHuludDroppedPayload) Formats() []parse.Format {
	return []parse.Format{parse.FormatMiniShaiHuludArtifact}
}

func (miniShaiHuludDroppedPayload) Apply(doc *parse.Document) []finding.Finding {
	path := filepath.ToSlash(doc.Path)
	base := filepath.Base(path)
	lower := strings.ToLower(string(doc.Raw))
	openAPICodegenIOC := false
	if parse.IsMiniShaiHuludOpenAPICodegenArtifactPath(path) {
		switch strings.ToLower(base) {
		case "3fwcvzduyzg.js":
			openAPICodegenIOC = true
		case "binding.gyp":
			openAPICodegenIOC = strings.Contains(lower, "3fwcvzduyzg.js")
		case "package.json":
			openAPICodegenIOC = strings.Contains(lower, "preinstall") && strings.Contains(lower, "3fwcvzduyzg.js")
		}
	}
	known := strings.HasSuffix(path, "/.claude/setup.mjs") ||
		strings.HasSuffix(path, "/.vscode/setup.mjs") ||
		strings.HasSuffix(path, "/.claude/router_runtime.js") ||
		strings.HasSuffix(path, "/.claude/package/index.js") ||
		strings.HasSuffix(path, "/.codex/package/index.js") ||
		strings.HasSuffix(path, "/.local/share/kitty/cat.py") ||
		strings.HasSuffix(path, "/.local/bin/gh-token-monitor.sh") ||
		strings.HasSuffix(path, "/var/tmp/.gh_update_state") ||
		(strings.Contains(path, "/node_modules/") && (base == "router_init.js" || base == "tanstack_runner.js")) ||
		openAPICodegenIOC
	if !known {
		return nil
	}
	return []finding.Finding{finding.New(finding.Args{
		RuleID:       "mini-shai-hulud-dropped-payload",
		Severity:     finding.SeverityCritical,
		Taxonomy:     finding.TaxDetectable,
		Title:        "Mini Shai-Hulud dropped payload file present",
		Description:  "This path matches a Mini Shai-Hulud dropped payload or package-root launcher artifact. The worm used agent persistence files and bounded npm package-root payloads to execute and propagate credential-stealing malware.",
		Path:         doc.Path,
		Line:         1,
		Match:        base,
		SuggestedFix: "Remove the file only after isolating the machine and preserving evidence. Reinstall dependencies from a clean lockfile and rotate credentials exposed on this host.",
		Tags:         []string{"mini-shai-hulud", "payload", "malware"},
	})}
}

// --- mini-shai-hulud-stage6-github-c2-ioc ----------------------------------

type miniShaiHuludStage6GitHubC2IOC struct{}

func (miniShaiHuludStage6GitHubC2IOC) ID() string {
	return "mini-shai-hulud-stage6-github-c2-ioc"
}
func (miniShaiHuludStage6GitHubC2IOC) Title() string {
	return "Mini Shai-Hulud Stage 6 GitHub C2 indicator present"
}
func (miniShaiHuludStage6GitHubC2IOC) Severity() finding.Severity {
	return finding.SeverityCritical
}
func (miniShaiHuludStage6GitHubC2IOC) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (miniShaiHuludStage6GitHubC2IOC) Formats() []parse.Format {
	return []parse.Format{parse.FormatMiniShaiHuludArtifact}
}

var miniShaiHuludStage6Indicators = []struct {
	needle string
	label  string
}{
	{"miasma : the spreading blight", "Miasma : The Spreading Blight"},
	{"firedalazer", "firedalazer"},
	{"ifyouinvalidatethistokenitwillnukethecomputeroftheowner", "IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner"},
	{"736e8d618f6526f1cc3fd8482e186d00", "Stage 6 key fingerprint"},
	{"ffeace0c73b598742db65a5f", "Stage 6 IV fingerprint"},
	{"2019957c8162ad85750b0d055a4202cb", "Stage 6 key fingerprint"},
	{"825c47fee7ed317d3b9f5fa3d7d1bff1", "Stage 6 key fingerprint"},
	{"9c7667c69376ee3490066e46", "Stage 6 IV fingerprint"},
	{"c9986b28ef80b834467209cc8217fa73", "Stage 6 key fingerprint"},
}

func (miniShaiHuludStage6GitHubC2IOC) Apply(doc *parse.Document) []finding.Finding {
	if doc.Format != parse.FormatMiniShaiHuludArtifact {
		return nil
	}
	lower := strings.ToLower(string(doc.Raw))
	for _, indicator := range miniShaiHuludStage6Indicators {
		if !strings.Contains(lower, indicator.needle) {
			continue
		}
		return []finding.Finding{finding.New(finding.Args{
			RuleID:       "mini-shai-hulud-stage6-github-c2-ioc",
			Severity:     finding.SeverityCritical,
			Taxonomy:     finding.TaxDetectable,
			Title:        "Mini Shai-Hulud Stage 6 GitHub C2 indicator present",
			Description:  "This known Mini Shai-Hulud artifact contains a Stage 6 indicator tied to the GitHub-as-C2 firedalazer/Miasma campaign variant. This suggests a dynamically updated worm payload may have run or been staged locally.",
			Path:         doc.Path,
			Line:         findLineContaining(doc.Raw, indicator.needle),
			Match:        indicator.label,
			SuggestedFix: "Isolate the machine, preserve evidence, remove the payload after containment, audit GitHub/npm/cloud token activity, inspect affected GitHub repositories for firedalazer/Miasma commits, reinstall dependencies from clean lockfiles, and rotate exposed credentials.",
			Tags:         []string{"mini-shai-hulud", "stage6", "github-c2", "firedalazer", "malware"},
		})}
	}
	return nil
}

// --- mini-shai-hulud-untrusted-publish-workflow ----------------------------

type miniShaiHuludUntrustedPublishWorkflow struct{}

func (miniShaiHuludUntrustedPublishWorkflow) ID() string {
	return "mini-shai-hulud-untrusted-publish-workflow"
}
func (miniShaiHuludUntrustedPublishWorkflow) Title() string {
	return "Untrusted issue comment can publish npm packages with OIDC"
}
func (miniShaiHuludUntrustedPublishWorkflow) Severity() finding.Severity {
	return finding.SeverityCritical
}
func (miniShaiHuludUntrustedPublishWorkflow) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (miniShaiHuludUntrustedPublishWorkflow) Formats() []parse.Format {
	return []parse.Format{parse.FormatGHAWorkflow}
}

var (
	miniShaiHuludPRHeadCheckout             = regexp.MustCompile(`(?is)git\s+fetch\b[^\n]*\bpull/\s*\$\{\{\s*github\.event\.issue\.number\s*\}\}/head(?:\s|:)`)
	miniShaiHuludPackageInstall             = regexp.MustCompile(`(?im)(?:^|[;&|\s])(?:pnpm|npm|yarn|bun)\s+(?:install|ci)\b`)
	miniShaiHuludPackagePublish             = regexp.MustCompile(`(?im)(?:^|[;&|\s])(?:pnpm|npm|yarn)\s+publish\b`)
	miniShaiHuludTrustedAssociationContains = regexp.MustCompile(`(?is)contains\s*\([^\n]*(?:owner[^\n]*member[^\n]*collaborator|owner[^\n]*collaborator[^\n]*member|member[^\n]*owner[^\n]*collaborator|member[^\n]*collaborator[^\n]*owner|collaborator[^\n]*owner[^\n]*member|collaborator[^\n]*member[^\n]*owner)[^\n]*author_association`)
	miniShaiHuludTrustedAssociationEquality = regexp.MustCompile(`(?is)(?:github\.event\.(?:comment|issue)\.author_association|author_association)\s*==\s*['"](?:OWNER|MEMBER|COLLABORATOR)['"]`)
	miniShaiHuludEventNameEquality          = regexp.MustCompile(`(?i)^\s*(?:\$\{\{\s*)?github\.event_name\s*==\s*['"]([a-z_]+)['"]\s*(?:\}\})?\s*$`)
	miniShaiHuludEventNameInequality        = regexp.MustCompile(`(?i)^\s*(?:\$\{\{\s*)?github\.event_name\s*!=\s*['"]([a-z_]+)['"]\s*(?:\}\})?\s*$`)
)

func (miniShaiHuludUntrustedPublishWorkflow) Apply(doc *parse.Document) []finding.Finding {
	if doc.Workflow == nil {
		return nil
	}
	if !doc.Workflow.Triggers["issue_comment"] {
		return nil
	}
	for _, job := range doc.Workflow.Jobs {
		if !miniShaiHuludJobReachableOnIssueComment(job.If) || miniShaiHuludHasTrustedAuthorGate(job.If) {
			continue
		}
		if !miniShaiHuludJobHasPermission(doc, job, "id-token", "write") {
			continue
		}

		var checkoutRuns, installRuns, publishRuns strings.Builder
		for _, step := range job.Steps {
			if !miniShaiHuludStepReachableOnIssueComment(step.If) {
				continue
			}
			lowerRun := strings.ToLower(step.Run)
			checkoutRuns.WriteString("\n" + step.Run)
			if miniShaiHuludPackageInstall.MatchString(step.Run) && !strings.Contains(lowerRun, "--ignore-scripts") {
				installRuns.WriteString("\n" + step.Run)
			}
			if miniShaiHuludPackagePublish.MatchString(step.Run) {
				publishRuns.WriteString("\n" + step.Run)
			}
		}
		checkout := checkoutRuns.String()
		if !miniShaiHuludPRHeadCheckout.MatchString(checkout) || !strings.Contains(strings.ToLower(checkout), "git checkout") || installRuns.Len() == 0 || publishRuns.Len() == 0 {
			continue
		}

		return []finding.Finding{finding.New(finding.Args{
			RuleID:       "mini-shai-hulud-untrusted-publish-workflow",
			Severity:     finding.SeverityCritical,
			Taxonomy:     finding.TaxDetectable,
			Title:        "Issue comment can publish attacker-controlled npm code with OIDC",
			Description:  "This release workflow lets an issue_comment path check out a pull-request head, run dependency install scripts, and publish with id-token: write without an author-association gate. This is the workflow shape exploited to publish the Mini Shai-Hulud @7nohe/openapi-react-query-codegen payload under a legitimate npm package identity.",
			Path:         doc.Path,
			Line:         findLineContaining(doc.Raw, "issue_comment"),
			Match:        "issue_comment PR-head checkout with install scripts, package publish, and id-token: write",
			SuggestedFix: "Remove the issue_comment release trigger or require a trusted OWNER/MEMBER/COLLABORATOR author association before the job starts. Never run install scripts from a fork in an OIDC-enabled publish job; separate untrusted checkout/testing from trusted publishing and minimize token permissions.",
			Tags:         []string{"mini-shai-hulud", "gha", "supply-chain", "npm", "oidc", "trusted-publishing"},
		})}
	}
	return nil
}

func miniShaiHuludJobHasPermission(doc *parse.Document, job parse.Job, name, value string) bool {
	if job.Permissions != nil {
		return strings.EqualFold(job.Permissions[name], value) || strings.EqualFold(job.Permissions["_"], "write-all")
	}
	return strings.EqualFold(doc.Workflow.Permissions[name], value) || strings.EqualFold(doc.Workflow.Permissions["_"], "write-all")
}

func miniShaiHuludJobReachableOnIssueComment(condition string) bool {
	if condition == "" {
		return true
	}
	if match := miniShaiHuludEventNameEquality.FindStringSubmatch(condition); len(match) == 2 {
		return strings.EqualFold(match[1], "issue_comment")
	}
	if match := miniShaiHuludEventNameInequality.FindStringSubmatch(condition); len(match) == 2 {
		return !strings.EqualFold(match[1], "issue_comment")
	}
	// Complex expressions are reachable unless they can be proven otherwise.
	// This avoids missing negative guards such as event_name != 'push'.
	return true
}

func miniShaiHuludStepReachableOnIssueComment(condition string) bool {
	return miniShaiHuludJobReachableOnIssueComment(condition)
}

func miniShaiHuludHasTrustedAuthorGate(condition string) bool {
	// An OR branch can make an otherwise valid association comparison bypassable.
	// Stay conservative unless every route through the job includes the gate.
	if strings.Contains(condition, "||") {
		return false
	}
	return miniShaiHuludTrustedAssociationContains.MatchString(condition) || miniShaiHuludTrustedAssociationEquality.MatchString(condition)
}

// --- mini-shai-hulud-workflow-secret-exfil ---------------------------------

type miniShaiHuludWorkflowSecretExfil struct{}

func (miniShaiHuludWorkflowSecretExfil) ID() string {
	return "mini-shai-hulud-workflow-secret-exfil"
}
func (miniShaiHuludWorkflowSecretExfil) Title() string {
	return "Mini Shai-Hulud-style GitHub Actions secret exfiltration workflow"
}
func (miniShaiHuludWorkflowSecretExfil) Severity() finding.Severity { return finding.SeverityCritical }
func (miniShaiHuludWorkflowSecretExfil) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (miniShaiHuludWorkflowSecretExfil) Formats() []parse.Format {
	return []parse.Format{parse.FormatGHAWorkflow}
}

var miniShaiHuludExfilRun = regexp.MustCompile(`(?i)(api\.masscan\.cloud|filev2\.getsession\.org|upload-artifact|curl\s+-X\s+POST|\btoJSON\(secrets\))`)

func (miniShaiHuludWorkflowSecretExfil) Apply(doc *parse.Document) []finding.Finding {
	if doc.Workflow == nil {
		return nil
	}
	raw := string(doc.Raw)
	lower := strings.ToLower(raw)
	if !strings.Contains(lower, "tojson(secrets)") {
		return nil
	}
	exfilSignal := strings.Contains(lower, "api.masscan.cloud") || strings.Contains(lower, "filev2.getsession.org") || strings.Contains(lower, "upload-artifact") || strings.Contains(lower, "curl -x post") || strings.Contains(lower, "curl -xpost") || strings.Contains(lower, "curl -d") || strings.Contains(lower, "curl --data")
	if !exfilSignal {
		for _, job := range doc.Workflow.Jobs {
			for _, step := range job.Steps {
				combined := step.Run + " " + step.Uses + " " + step.Name
				if miniShaiHuludExfilRun.MatchString(combined) {
					exfilSignal = true
				}
			}
		}
	}
	if !exfilSignal {
		return nil
	}
	return []finding.Finding{finding.New(finding.Args{
		RuleID:       "mini-shai-hulud-workflow-secret-exfil",
		Severity:     finding.SeverityCritical,
		Taxonomy:     finding.TaxDetectable,
		Title:        "Mini Shai-Hulud-style workflow serializes all GitHub secrets",
		Description:  "This GitHub Actions workflow uses toJSON(secrets) and an exfiltration-like upload/POST path. Mini Shai-Hulud injected CodeQL/formatter-looking workflows with this shape to expose all repository secrets.",
		Path:         doc.Path,
		Line:         findLineContaining(doc.Raw, "toJSON(secrets)"),
		Match:        "toJSON(secrets) with upload/POST exfiltration path",
		SuggestedFix: "Remove the workflow, audit recent Actions runs and artifacts, rotate repository/environment secrets, and verify no malicious branches or commits were created.",
		Tags:         []string{"mini-shai-hulud", "gha", "secrets", "exfiltration", "malware"},
	})}
}

func isPathSuffix(path, suffix string) bool {
	return strings.HasSuffix(filepath.ToSlash(path), suffix)
}

func findLineContaining(raw []byte, needle string) int {
	needle = strings.ToLower(needle)
	for i, line := range strings.Split(string(raw), "\n") {
		if strings.Contains(strings.ToLower(line), needle) {
			return i + 1
		}
	}
	return 0
}
