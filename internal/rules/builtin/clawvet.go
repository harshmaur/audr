package builtin

import (
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

const clawVetKnownJWTSecret = "clawvet-dev-secret-change-me"

type clawVetHardcodedJWTSecret struct{}

func (clawVetHardcodedJWTSecret) ID() string { return "clawvet-hardcoded-jwt-secret" }
func (clawVetHardcodedJWTSecret) Title() string {
	return "ClawVet self-hosted API uses a known JWT secret"
}
func (clawVetHardcodedJWTSecret) Severity() finding.Severity { return finding.SeverityCritical }
func (clawVetHardcodedJWTSecret) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (clawVetHardcodedJWTSecret) Formats() []parse.Format {
	return []parse.Format{parse.FormatClawVetAuthSource, parse.FormatEnv}
}

func (clawVetHardcodedJWTSecret) Apply(doc *parse.Document) []finding.Finding {
	line := 1
	switch doc.Format {
	case parse.FormatClawVetAuthSource:
		if !strings.Contains(string(doc.Raw), clawVetKnownJWTSecret) {
			return nil
		}
		line = findLineContaining(doc.Raw, clawVetKnownJWTSecret)
	case parse.FormatEnv:
		if doc.Env == nil || doc.Env.Vars["JWT_SECRET"] != clawVetKnownJWTSecret {
			return nil
		}
		if doc.Env.Lines["JWT_SECRET"] > 0 {
			line = doc.Env.Lines["JWT_SECRET"]
		}
	default:
		return nil
	}

	return []finding.Finding{finding.New(finding.Args{
		RuleID:       "clawvet-hardcoded-jwt-secret",
		Severity:     finding.SeverityCritical,
		Taxonomy:     finding.TaxDetectable,
		Title:        "ClawVet self-hosted API uses a known JWT secret",
		Description:  "CVE-2026-62241: ClawVet self-hosted apps/api releases before 0.7.5 can use a public fallback JWT secret, allowing an unauthenticated attacker to forge cg_session cookies after obtaining a user ID. The npm CLI alone is not affected.",
		Path:         doc.Path,
		Line:         line,
		Match:        "known ClawVet fallback JWT secret is configured or embedded",
		SuggestedFix: "Upgrade the ClawVet self-hosted API to 0.7.5 or later, require a cryptographically random JWT_SECRET at startup, rotate any previously used JWT secret, revoke active sessions and API keys, and restrict scan-list/auth endpoints to the authenticated caller.",
		Tags:         []string{"cve", "clawvet", "self-hosted-api", "hardcoded-secret", "authentication-bypass", "cwe-321"},
	})}
}
