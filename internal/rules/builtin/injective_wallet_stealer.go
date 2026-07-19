package builtin

import (
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

type injectiveSDKWalletSecretExfilIOC struct{}

func (injectiveSDKWalletSecretExfilIOC) ID() string {
	return "injective-sdk-wallet-secret-exfil-ioc"
}
func (injectiveSDKWalletSecretExfilIOC) Title() string {
	return "Injective SDK wallet-secret exfiltration payload present"
}
func (injectiveSDKWalletSecretExfilIOC) Severity() finding.Severity {
	return finding.SeverityCritical
}
func (injectiveSDKWalletSecretExfilIOC) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (injectiveSDKWalletSecretExfilIOC) Formats() []parse.Format {
	return []parse.Format{parse.FormatNPMMalwareArtifact}
}

func (injectiveSDKWalletSecretExfilIOC) Apply(doc *parse.Document) []finding.Finding {
	if doc.Format != parse.FormatNPMMalwareArtifact || !parse.IsInjectiveWalletStealerArtifactPath(doc.Path) {
		return nil
	}
	text := string(doc.Raw)
	for _, marker := range []string{
		"trackKeyDerivation",
		"String.fromCharCode",
		"X-Request-Id",
		"application/grpc-web+proto",
	} {
		if !strings.Contains(text, marker) {
			return nil
		}
	}

	return []finding.Finding{finding.New(finding.Args{
		RuleID:       "injective-sdk-wallet-secret-exfil-ioc",
		Severity:     finding.SeverityCritical,
		Taxonomy:     finding.TaxDetectable,
		Title:        "Injective SDK wallet-secret exfiltration payload present",
		Description:  "This bounded source or generated-bundle evidence matches the malicious key-derivation telemetry shipped in @injectivelabs/sdk-ts 1.20.21. The payload captured BIP-39 mnemonics and string-form private keys, encoded them, and sent them in an X-Request-Id header disguised as gRPC-Web traffic.",
		Path:         doc.Path,
		Line:         findLineContaining(doc.Raw, "trackKeyDerivation"),
		Match:        "wallet key-derivation hook plus obfuscated X-Request-Id exfiltration markers",
		SuggestedFix: "Isolate the machine, preserve the affected bundle for incident response, remove @injectivelabs/sdk-ts 1.20.21, reinstall dependencies from a clean lockfile at 1.20.23 or later, and rotate every wallet mnemonic or private key used by the compromised SDK from a clean machine.",
		Tags:         []string{"injective", "npm", "supply-chain", "malware", "wallet", "credential-theft", "secret-exfiltration"},
	})}
}
