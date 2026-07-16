package builtin

import (
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

type asyncAPIMiasmaRATIOC struct{}

func (asyncAPIMiasmaRATIOC) ID() string { return "asyncapi-miasma-rat-ioc" }
func (asyncAPIMiasmaRATIOC) Title() string {
	return "AsyncAPI Miasma RAT campaign indicator present"
}
func (asyncAPIMiasmaRATIOC) Severity() finding.Severity { return finding.SeverityCritical }
func (asyncAPIMiasmaRATIOC) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (asyncAPIMiasmaRATIOC) Formats() []parse.Format {
	return []parse.Format{parse.FormatAsyncAPIMiasmaArtifact}
}

var asyncAPIMiasmaIndicators = []struct {
	needle string
	label  string
}{
	{"miasma-train-p1", "Miasma campaign marker"},
	{"qmqobzsp1wrprpseq56qnyq7eczh5bg5k1fnjt4suwwhb9", "generator-family IPFS CID"},
	{"qmet4fhsaawmbuxndfrehwgiydeswy4ysys9wikuw5jgyf", "specs IPFS CID"},
	{"rt-vault-master-key-32b-aaaaaaaa", "Miasma HKDF master-key marker"},
	{"rt-file-key-material-v1", "Miasma file-key marker"},
	{"0x12c37a86a0ed0bebe5d1d6a43e42f07860eac710", "Miasma Ethereum contract"},
	{"85.137.53.71", "Miasma C2 address"},
}

func (asyncAPIMiasmaRATIOC) Apply(doc *parse.Document) []finding.Finding {
	if doc.Format != parse.FormatAsyncAPIMiasmaArtifact || !parse.IsAsyncAPIMiasmaArtifactPath(doc.Path) {
		return nil
	}
	match := "platform-specific NodeJS/sync.js drop path"
	line := 1
	if !parse.IsAsyncAPIMiasmaDropPath(doc.Path) {
		lower := strings.ToLower(string(doc.Raw))
		match = ""
		for _, indicator := range asyncAPIMiasmaIndicators {
			needle := strings.ReplaceAll(indicator.needle, " ", "")
			if !strings.Contains(lower, needle) {
				continue
			}
			match = indicator.label
			line = findLineContaining(doc.Raw, needle)
			break
		}
		if match == "" {
			return nil
		}
	}
	return []finding.Finding{finding.New(finding.Args{
		RuleID:       "asyncapi-miasma-rat-ioc",
		Severity:     finding.SeverityCritical,
		Taxonomy:     finding.TaxDetectable,
		Title:        "AsyncAPI Miasma RAT campaign indicator present",
		Description:  "This bounded file/path evidence matches the July 2026 AsyncAPI npm compromise that downloaded Miasma RAT, persisted as NodeJS/sync.js, harvested developer and CI credentials, and contacted fixed command-and-control infrastructure.",
		Path:         doc.Path,
		Line:         line,
		Match:        match,
		SuggestedFix: "Isolate the machine, preserve the payload for incident response, remove affected AsyncAPI packages and the sync.js persistence artifact after containment, reinstall dependencies from clean lockfiles, and rotate npm, GitHub, SSH, cloud, browser, and CI credentials reachable from the host.",
		Tags:         []string{"asyncapi", "miasma", "npm", "supply-chain", "credential-theft", "persistence", "malware"},
	})}
}
