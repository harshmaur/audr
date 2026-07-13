package builtin

import (
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

const (
	nodemonSudoPinataCID = "bafkreigjnxn5vnn34rc5r43ajwwkmk4akqpm4awmq5gdhakgszpeqiffsu"
	nodemonSudoXRGF3     = "aHR0cHM6Ly9qc29ua2VlcGVyLmNvbS9iL1hSR0Yz"
	nodemonSudo4NAKK     = "aHR0cHM6Ly9qc29ua2VlcGVyLmNvbS9iLzROQUtL"
)

type nodemonSudoTslintConfBackdoorIOC struct{}

func (nodemonSudoTslintConfBackdoorIOC) ID() string {
	return "nodemon-sudo-tslint-conf-backdoor-ioc"
}
func (nodemonSudoTslintConfBackdoorIOC) Title() string {
	return "nodemon-sudo / tslint-conf runtime backdoor present"
}
func (nodemonSudoTslintConfBackdoorIOC) Severity() finding.Severity {
	return finding.SeverityCritical
}
func (nodemonSudoTslintConfBackdoorIOC) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (nodemonSudoTslintConfBackdoorIOC) Formats() []parse.Format {
	return []parse.Format{parse.FormatNPMMalwareArtifact}
}

func (nodemonSudoTslintConfBackdoorIOC) Apply(doc *parse.Document) []finding.Finding {
	path := strings.ReplaceAll(doc.Path, string(rune(92)), "/")
	raw := string(doc.Raw)
	lower := strings.ToLower(raw)
	match := ""
	lineNeedle := ""

	switch {
	case strings.HasSuffix(path, "/node_modules/tslint-conf/lib/caller.js") &&
		containsTslintConfCallerBackdoor(raw, lower):
		match = "tslint-conf fetched-code executor"
		if strings.Contains(lower, nodemonSudoPinataCID) {
			lineNeedle = nodemonSudoPinataCID
		} else {
			lineNeedle = "function.constructor"
		}
	case strings.HasSuffix(path, "/node_modules/tslint-conf/index.js") &&
		containsTslintConfRuntimeTrigger(lower):
		match = "tslint-conf detached caller.js runtime trigger"
		lineNeedle = "caller.js"
	case strings.HasSuffix(path, "/node_modules/tslint-conf/lib/const.js") &&
		containsTslintConfDeadDrop(raw, lower):
		match = "tslint-conf campaign dead-drop configuration"
		lineNeedle = "dev_api_key"
	default:
		return nil
	}

	return []finding.Finding{finding.New(finding.Args{
		RuleID:       "nodemon-sudo-tslint-conf-backdoor-ioc",
		Severity:     finding.SeverityCritical,
		Taxonomy:     finding.TaxDetectable,
		Title:        "nodemon-sudo / tslint-conf runtime backdoor present",
		Description:  "This file matches a bounded source IOC from the July 2026 nodemon-sudo / tslint-conf npm backdoor. The runtime trigger launches a detached worker that fetches attacker-controlled JavaScript and executes it with Node require access.",
		Path:         doc.Path,
		Line:         findLineContaining(doc.Raw, lineNeedle),
		Match:        match,
		SuggestedFix: "Isolate the machine, preserve evidence, remove nodemon-sudo and tslint-conf, reinstall dependencies from a clean lockfile, inspect outbound requests to the documented Pinata and jsonkeeper infrastructure, and rotate credentials and tokens reachable from the host.",
		Tags:         []string{"nodemon-sudo", "tslint-conf", "npm", "supply-chain", "backdoor", "malware"},
	})}
}

func containsTslintConfCallerBackdoor(raw, lower string) bool {
	campaignEndpoint := strings.Contains(lower, nodemonSudoPinataCID) ||
		strings.Contains(raw, nodemonSudoXRGF3)
	return campaignEndpoint &&
		strings.Contains(lower, "function.constructor") &&
		strings.Contains(lower, "require")
}

func containsTslintConfRuntimeTrigger(lower string) bool {
	return strings.Contains(lower, "caller.js") &&
		strings.Contains(lower, "path.resolve") &&
		strings.Contains(lower, "__dirname") &&
		strings.Contains(lower, "json.stringify") &&
		strings.Contains(lower, "spawn") &&
		strings.Contains(lower, "detached") &&
		strings.Contains(lower, "stdio") &&
		strings.Contains(lower, "ignore") &&
		strings.Contains(lower, ".unref")
}

func containsTslintConfDeadDrop(raw, lower string) bool {
	return (strings.Contains(raw, nodemonSudoXRGF3) || strings.Contains(raw, nodemonSudo4NAKK)) &&
		strings.Contains(lower, "dev_api_key") &&
		strings.Contains(lower, "dev_secret_key")
}
