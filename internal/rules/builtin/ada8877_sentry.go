package builtin

import (
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

type ada8877SentryDependencyConfusionIOC struct{}

func (ada8877SentryDependencyConfusionIOC) ID() string {
	return "ada8877-sentry-dependency-confusion-ioc"
}
func (ada8877SentryDependencyConfusionIOC) Title() string {
	return "ada8877 dependency-confusion Sentry beacon present"
}
func (ada8877SentryDependencyConfusionIOC) Severity() finding.Severity {
	return finding.SeverityHigh
}
func (ada8877SentryDependencyConfusionIOC) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (ada8877SentryDependencyConfusionIOC) Formats() []parse.Format {
	return []parse.Format{parse.FormatPackageJSON, parse.FormatNPMMalwareArtifact}
}

func (ada8877SentryDependencyConfusionIOC) Apply(doc *parse.Document) []finding.Finding {
	match := ""
	line := 1

	switch doc.Format {
	case parse.FormatPackageJSON:
		if doc.PackageJSON == nil || !isAda8877CampaignPackagePath(doc.Path, "package.json") {
			return nil
		}
		var metadata struct {
			Scripts map[string]string `json:"scripts"`
		}
		if json.Unmarshal(doc.Raw, &metadata) != nil ||
			strings.TrimSpace(metadata.Scripts["preinstall"]) != "npm install @sentry/node && node examples/verify.js" ||
			!isAda8877CampaignPackageName(doc.PackageJSON.Name) {
			return nil
		}
		match = doc.PackageJSON.Name + " with campaign preinstall hook"
		line = findLineContaining(doc.Raw, "preinstall")
	case parse.FormatNPMMalwareArtifact:
		if !parse.IsAda8877SentryVerifyArtifactPath(doc.Path) || !containsAda8877SentryBeacon(doc.Raw) {
			return nil
		}
		match = "attacker Sentry host with default PII and Cloudflare trace markers"
		line = findLineContaining(doc.Raw, "o4510485815754752.ingest.us.sentry.io")
	default:
		return nil
	}

	return []finding.Finding{finding.New(finding.Args{
		RuleID:       "ada8877-sentry-dependency-confusion-ioc",
		Severity:     finding.SeverityHigh,
		Taxonomy:     finding.TaxDetectable,
		Title:        "ada8877 dependency-confusion Sentry beacon present",
		Description:  "This bounded package-root evidence matches the July 2026 ada8877 npm dependency-confusion campaign. Its install-time payload collected the host's public IP and default PII, then beaconed the telemetry to an attacker-controlled Sentry organization.",
		Path:         doc.Path,
		Line:         line,
		Match:        match,
		SuggestedFix: "Isolate the machine, preserve evidence, remove the affected syft-acp or @edgecommons lookalike package, reinstall dependencies from a clean lockfile, inspect install-time network activity, and rotate credentials reachable from the host if compromise is confirmed.",
		Tags:         []string{"ada8877", "sentry", "npm", "dependency-confusion", "supply-chain", "reconnaissance", "malware"},
	})}
}

func isAda8877CampaignPackageName(name string) bool {
	switch name {
	case "syft-acp-atoms", "syft-acp-uikit", "syft-acp-core", "@edgecommons/streamlog-node", "@edgecommons/edgecommons":
		return true
	default:
		return false
	}
}

func isAda8877CampaignPackagePath(path, leaf string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"))
	marker := "/node_modules/"
	idx := strings.LastIndex(normalized, marker)
	if idx < 0 {
		return false
	}
	rel := normalized[idx+len(marker):]
	for _, prefix := range []string{
		"syft-acp-atoms/",
		"syft-acp-uikit/",
		"syft-acp-core/",
		"@edgecommons/streamlog-node/",
		"@edgecommons/edgecommons/",
	} {
		if rel == prefix+leaf {
			return true
		}
	}
	return false
}

func containsAda8877SentryBeacon(raw []byte) bool {
	lower := strings.ToLower(string(raw))
	return strings.Contains(lower, "o4510485815754752.ingest.us.sentry.io") &&
		strings.Contains(lower, "senddefaultpii") &&
		strings.Contains(lower, "/cdn-cgi/trace")
}
