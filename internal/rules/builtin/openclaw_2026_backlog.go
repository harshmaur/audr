package builtin

import (
	"fmt"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

type openclawMatrixDMPairingAuthBypass struct{}
type openclawBlueBubblesWebhookAuthBypass struct{}
type openclawACPAttachmentPathTraversal struct{}
type openclawJQEnvDisclosure struct{}
type openclawLocalMediaRootSelfWhitelist struct{}
type openclawDevicePairBootstrapScopeBypass struct{}
type openclawSlackPluginApprovalGateBypass struct{}
type openclawQQBotAdminPolicyBypass struct{}
type openclawQQBotApprovalButtonBypass struct{}
type openclawBrowserTabSSRFReuse struct{}
type openclawGatewayChatSendScopeBypass struct{}
type openclawNodePairingReconnectScopeConfusion struct{}
type openclawShellOptionRevalidationBypass struct{}
type openclawTelegramCallbackAllowFromBypass struct{}
type openclawMarketplaceExtensionMetadataRedirect struct{}
type openclawMatrixAllowFromDisplayNameBypass struct{}

func (openclawMatrixDMPairingAuthBypass) ID() string { return "openclaw-matrix-dm-pairing-auth-bypass" }
func (openclawMatrixDMPairingAuthBypass) Title() string {
	return "OpenClaw version is vulnerable to Matrix DM pairing authorization bypass"
}
func (openclawMatrixDMPairingAuthBypass) Severity() finding.Severity { return finding.SeverityHigh }
func (openclawMatrixDMPairingAuthBypass) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (openclawMatrixDMPairingAuthBypass) Formats() []parse.Format {
	return []parse.Format{parse.FormatPackageJSON}
}
func (openclawMatrixDMPairingAuthBypass) Apply(doc *parse.Document) []finding.Finding {
	return openclawPackageVersionFindings(doc, vulnerableOpenClawMatrixDMPairingAuthBypassVersion, openclawMatrixDMPairingAuthBypassFinding)
}

func (openclawBlueBubblesWebhookAuthBypass) ID() string {
	return "openclaw-bluebubbles-webhook-auth-bypass"
}
func (openclawBlueBubblesWebhookAuthBypass) Title() string {
	return "OpenClaw version is vulnerable to BlueBubbles webhook authorization bypass"
}
func (openclawBlueBubblesWebhookAuthBypass) Severity() finding.Severity {
	return finding.SeverityMedium
}
func (openclawBlueBubblesWebhookAuthBypass) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (openclawBlueBubblesWebhookAuthBypass) Formats() []parse.Format {
	return []parse.Format{parse.FormatPackageJSON}
}
func (openclawBlueBubblesWebhookAuthBypass) Apply(doc *parse.Document) []finding.Finding {
	return openclawPackageVersionFindings(doc, vulnerableOpenClawBlueBubblesWebhookAuthBypassVersion, openclawBlueBubblesWebhookAuthBypassFinding)
}

func (openclawACPAttachmentPathTraversal) ID() string {
	return "openclaw-acp-attachment-path-traversal"
}
func (openclawACPAttachmentPathTraversal) Title() string {
	return "OpenClaw version is vulnerable to ACP attachment path traversal"
}
func (openclawACPAttachmentPathTraversal) Severity() finding.Severity { return finding.SeverityHigh }
func (openclawACPAttachmentPathTraversal) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (openclawACPAttachmentPathTraversal) Formats() []parse.Format {
	return []parse.Format{parse.FormatPackageJSON}
}
func (openclawACPAttachmentPathTraversal) Apply(doc *parse.Document) []finding.Finding {
	return openclawPackageVersionFindings(doc, vulnerableOpenClawACPAttachmentPathTraversalVersion, openclawACPAttachmentPathTraversalFinding)
}

func (openclawJQEnvDisclosure) ID() string { return "openclaw-jq-env-disclosure" }
func (openclawJQEnvDisclosure) Title() string {
	return "OpenClaw version is vulnerable to jq environment disclosure"
}
func (openclawJQEnvDisclosure) Severity() finding.Severity { return finding.SeverityHigh }
func (openclawJQEnvDisclosure) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (openclawJQEnvDisclosure) Formats() []parse.Format {
	return []parse.Format{parse.FormatPackageJSON}
}
func (openclawJQEnvDisclosure) Apply(doc *parse.Document) []finding.Finding {
	return openclawPackageVersionFindings(doc, vulnerableOpenClawJQEnvDisclosureVersion, openclawJQEnvDisclosureFinding)
}

func (openclawLocalMediaRootSelfWhitelist) ID() string {
	return "openclaw-local-media-root-self-whitelist"
}
func (openclawLocalMediaRootSelfWhitelist) Title() string {
	return "OpenClaw version is vulnerable to local media root self-whitelisting"
}
func (openclawLocalMediaRootSelfWhitelist) Severity() finding.Severity { return finding.SeverityHigh }
func (openclawLocalMediaRootSelfWhitelist) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (openclawLocalMediaRootSelfWhitelist) Formats() []parse.Format {
	return []parse.Format{parse.FormatPackageJSON}
}
func (openclawLocalMediaRootSelfWhitelist) Apply(doc *parse.Document) []finding.Finding {
	return openclawPackageVersionFindings(doc, vulnerableOpenClawLocalMediaRootSelfWhitelistVersion, openclawLocalMediaRootSelfWhitelistFinding)
}

func (openclawDevicePairBootstrapScopeBypass) ID() string {
	return "openclaw-device-pair-bootstrap-scope-bypass"
}
func (openclawDevicePairBootstrapScopeBypass) Title() string {
	return "OpenClaw version is vulnerable to device-pair bootstrap scope bypass"
}
func (openclawDevicePairBootstrapScopeBypass) Severity() finding.Severity {
	return finding.SeverityHigh
}
func (openclawDevicePairBootstrapScopeBypass) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (openclawDevicePairBootstrapScopeBypass) Formats() []parse.Format {
	return []parse.Format{parse.FormatPackageJSON}
}
func (openclawDevicePairBootstrapScopeBypass) Apply(doc *parse.Document) []finding.Finding {
	return openclawPackageVersionFindings(doc, vulnerableOpenClawDevicePairBootstrapScopeBypassVersion, openclawDevicePairBootstrapScopeBypassFinding)
}

func (openclawSlackPluginApprovalGateBypass) ID() string {
	return "openclaw-slack-plugin-approval-gate-bypass"
}
func (openclawSlackPluginApprovalGateBypass) Title() string {
	return "OpenClaw version is vulnerable to Slack plugin approval gate bypass"
}
func (openclawSlackPluginApprovalGateBypass) Severity() finding.Severity {
	return finding.SeverityMedium
}
func (openclawSlackPluginApprovalGateBypass) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (openclawSlackPluginApprovalGateBypass) Formats() []parse.Format {
	return []parse.Format{parse.FormatPackageJSON}
}
func (openclawSlackPluginApprovalGateBypass) Apply(doc *parse.Document) []finding.Finding {
	return openclawPackageVersionFindings(doc, vulnerableOpenClawSlackPluginApprovalGateBypassVersion, openclawSlackPluginApprovalGateBypassFinding)
}

func (openclawQQBotAdminPolicyBypass) ID() string { return "openclaw-qqbot-admin-policy-bypass" }
func (openclawQQBotAdminPolicyBypass) Title() string {
	return "OpenClaw version is vulnerable to QQBot admin policy bypass"
}
func (openclawQQBotAdminPolicyBypass) Severity() finding.Severity { return finding.SeverityMedium }
func (openclawQQBotAdminPolicyBypass) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (openclawQQBotAdminPolicyBypass) Formats() []parse.Format {
	return []parse.Format{parse.FormatPackageJSON}
}
func (openclawQQBotAdminPolicyBypass) Apply(doc *parse.Document) []finding.Finding {
	return openclawPackageVersionFindings(doc, vulnerableOpenClawQQBotAdminPolicyBypassVersion, openclawQQBotAdminPolicyBypassFinding)
}

func (openclawQQBotApprovalButtonBypass) ID() string { return "openclaw-qqbot-approval-button-bypass" }
func (openclawQQBotApprovalButtonBypass) Title() string {
	return "OpenClaw version is vulnerable to QQBot approval button approver bypass"
}
func (openclawQQBotApprovalButtonBypass) Severity() finding.Severity { return finding.SeverityHigh }
func (openclawQQBotApprovalButtonBypass) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (openclawQQBotApprovalButtonBypass) Formats() []parse.Format {
	return []parse.Format{parse.FormatPackageJSON}
}
func (openclawQQBotApprovalButtonBypass) Apply(doc *parse.Document) []finding.Finding {
	return openclawPackageVersionFindings(doc, vulnerableOpenClawQQBotApprovalButtonBypassVersion, openclawQQBotApprovalButtonBypassFinding)
}

func (openclawBrowserTabSSRFReuse) ID() string { return "openclaw-browser-tab-ssrf-reuse" }
func (openclawBrowserTabSSRFReuse) Title() string {
	return "OpenClaw version is vulnerable to browser tab SSRF policy reuse"
}
func (openclawBrowserTabSSRFReuse) Severity() finding.Severity { return finding.SeverityMedium }
func (openclawBrowserTabSSRFReuse) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (openclawBrowserTabSSRFReuse) Formats() []parse.Format {
	return []parse.Format{parse.FormatPackageJSON}
}
func (openclawBrowserTabSSRFReuse) Apply(doc *parse.Document) []finding.Finding {
	return openclawPackageVersionFindings(doc, vulnerableOpenClawBrowserTabSSRFReuseVersion, openclawBrowserTabSSRFReuseFinding)
}

func (openclawGatewayChatSendScopeBypass) ID() string {
	return "openclaw-gateway-chat-send-scope-bypass"
}
func (openclawGatewayChatSendScopeBypass) Title() string {
	return "OpenClaw version is vulnerable to Gateway chat.send scope bypass"
}
func (openclawGatewayChatSendScopeBypass) Severity() finding.Severity { return finding.SeverityHigh }
func (openclawGatewayChatSendScopeBypass) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (openclawGatewayChatSendScopeBypass) Formats() []parse.Format {
	return []parse.Format{parse.FormatPackageJSON}
}
func (openclawGatewayChatSendScopeBypass) Apply(doc *parse.Document) []finding.Finding {
	return openclawPackageVersionFindings(doc, vulnerableOpenClawGatewayChatSendScopeBypassVersion, openclawGatewayChatSendScopeBypassFinding)
}

func (openclawNodePairingReconnectScopeConfusion) ID() string {
	return "openclaw-node-pairing-reconnect-scope-confusion"
}
func (openclawNodePairingReconnectScopeConfusion) Title() string {
	return "OpenClaw version is vulnerable to node pairing reconnection scope confusion"
}
func (openclawNodePairingReconnectScopeConfusion) Severity() finding.Severity {
	return finding.SeverityCritical
}
func (openclawNodePairingReconnectScopeConfusion) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (openclawNodePairingReconnectScopeConfusion) Formats() []parse.Format {
	return []parse.Format{parse.FormatPackageJSON}
}
func (openclawNodePairingReconnectScopeConfusion) Apply(doc *parse.Document) []finding.Finding {
	return openclawPackageVersionFindings(doc, vulnerableOpenClawNodePairingReconnectScopeConfusionVersion, openclawNodePairingReconnectScopeConfusionFinding)
}

func (openclawShellOptionRevalidationBypass) ID() string {
	return "openclaw-shell-option-revalidation-bypass"
}
func (openclawShellOptionRevalidationBypass) Title() string {
	return "OpenClaw version is vulnerable to shell option revalidation bypass"
}
func (openclawShellOptionRevalidationBypass) Severity() finding.Severity {
	return finding.SeverityHigh
}
func (openclawShellOptionRevalidationBypass) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (openclawShellOptionRevalidationBypass) Formats() []parse.Format {
	return []parse.Format{parse.FormatPackageJSON}
}
func (openclawShellOptionRevalidationBypass) Apply(doc *parse.Document) []finding.Finding {
	return openclawPackageVersionFindings(doc, vulnerableOpenClawShellOptionRevalidationBypassVersion, openclawShellOptionRevalidationBypassFinding)
}

func (openclawTelegramCallbackAllowFromBypass) ID() string {
	return "openclaw-telegram-callback-allowfrom-bypass"
}
func (openclawTelegramCallbackAllowFromBypass) Title() string {
	return "OpenClaw version is vulnerable to Telegram callback allowFrom bypass"
}
func (openclawTelegramCallbackAllowFromBypass) Severity() finding.Severity {
	return finding.SeverityHigh
}
func (openclawTelegramCallbackAllowFromBypass) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (openclawTelegramCallbackAllowFromBypass) Formats() []parse.Format {
	return []parse.Format{parse.FormatPackageJSON}
}
func (openclawTelegramCallbackAllowFromBypass) Apply(doc *parse.Document) []finding.Finding {
	return openclawPackageVersionFindings(doc, vulnerableOpenClawTelegramCallbackAllowFromBypassVersion, openclawTelegramCallbackAllowFromBypassFinding)
}

func (openclawMarketplaceExtensionMetadataRedirect) ID() string {
	return "openclaw-marketplace-extension-metadata-redirect"
}
func (openclawMarketplaceExtensionMetadataRedirect) Title() string {
	return "OpenClaw version is vulnerable to marketplace extension metadata redirect"
}
func (openclawMarketplaceExtensionMetadataRedirect) Severity() finding.Severity {
	return finding.SeverityHigh
}
func (openclawMarketplaceExtensionMetadataRedirect) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (openclawMarketplaceExtensionMetadataRedirect) Formats() []parse.Format {
	return []parse.Format{parse.FormatPackageJSON}
}
func (openclawMarketplaceExtensionMetadataRedirect) Apply(doc *parse.Document) []finding.Finding {
	return openclawPackageVersionFindings(doc, vulnerableOpenClawMarketplaceExtensionMetadataRedirectVersion, openclawMarketplaceExtensionMetadataRedirectFinding)
}

func (openclawMatrixAllowFromDisplayNameBypass) ID() string {
	return "openclaw-matrix-allowfrom-displayname-bypass"
}
func (openclawMatrixAllowFromDisplayNameBypass) Title() string {
	return "OpenClaw version is vulnerable to Matrix allowFrom display-name bypass"
}
func (openclawMatrixAllowFromDisplayNameBypass) Severity() finding.Severity {
	return finding.SeverityHigh
}
func (openclawMatrixAllowFromDisplayNameBypass) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (openclawMatrixAllowFromDisplayNameBypass) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest, parse.FormatPackageJSON}
}
func (openclawMatrixAllowFromDisplayNameBypass) Apply(doc *parse.Document) []finding.Finding {
	return openclawPackageVersionFindings(doc, vulnerableOpenClawMatrixAllowFromDisplayNameBypassVersion, openclawMatrixAllowFromDisplayNameBypassFinding)
}

func openclawPackageVersionFindings(doc *parse.Document, vulnerable func(string) bool, makeFinding func(string, string) finding.Finding) []finding.Finding {
	if doc.DependencyManifest == nil {
		return nil
	}
	for _, dep := range doc.DependencyManifest.Dependencies {
		if dep.Name == "openclaw" && vulnerable(dep.Version) {
			f := makeFinding(doc.Path, fmt.Sprintf("openclaw@%s", dep.Version))
			f.Line = dep.Line
			return []finding.Finding{f}
		}
	}
	return nil
}

func vulnerableOpenClawMatrixDMPairingAuthBypassVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 4, 15})
}
func vulnerableOpenClawBlueBubblesWebhookAuthBypassVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 2, 12})
}
func vulnerableOpenClawACPAttachmentPathTraversalVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 3, 31})
}
func vulnerableOpenClawJQEnvDisclosureVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 3, 28})
}
func vulnerableOpenClawLocalMediaRootSelfWhitelistVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 3, 31})
}
func vulnerableOpenClawDevicePairBootstrapScopeBypassVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 5, 4})
}
func vulnerableOpenClawSlackPluginApprovalGateBypassVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 5, 12})
}
func vulnerableOpenClawQQBotAdminPolicyBypassVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 4, 29})
}
func vulnerableOpenClawQQBotApprovalButtonBypassVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 5, 18})
}
func vulnerableOpenClawBrowserTabSSRFReuseVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 4, 29})
}
func vulnerableOpenClawGatewayChatSendScopeBypassVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 5, 18})
}
func vulnerableOpenClawNodePairingReconnectScopeConfusionVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 5, 27})
}
func vulnerableOpenClawShellOptionRevalidationBypassVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 5, 12})
}
func vulnerableOpenClawTelegramCallbackAllowFromBypassVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 5, 6})
}
func vulnerableOpenClawMarketplaceExtensionMetadataRedirectVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 5, 18})
}
func vulnerableOpenClawMatrixAllowFromDisplayNameBypassVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 5, 7})
}

func openclawMatrixDMPairingAuthBypassFinding(path, match string) finding.Finding {
	return openclawBacklogFinding(path, match, "openclaw-matrix-dm-pairing-auth-bypass", finding.SeverityHigh, "OpenClaw before 2026.4.15 trusts Matrix DM pairing stores for room control commands", "CVE-2026-44110: OpenClaw before 2026.4.15 trusts DM pairing store state for Matrix room control-command authorization, allowing authorization bypass in agent-control rooms.", "Upgrade OpenClaw to 2026.4.15 or later and review Matrix room control-command pairings created by vulnerable versions.", []string{"cve", "openclaw", "package-json", "matrix", "auth-bypass"})
}
func openclawBlueBubblesWebhookAuthBypassFinding(path, match string) finding.Finding {
	return openclawBacklogFinding(path, match, "openclaw-bluebubbles-webhook-auth-bypass", finding.SeverityMedium, "OpenClaw before 2026.2.12 exposes BlueBubbles webhook auth bypass", "CVE-2026-8305: OpenClaw's BlueBubbles webhook handler accepted unauthenticated or insufficiently authorized webhook requests before the fixed release, letting external requests reach agent-control handling.", "Upgrade OpenClaw to 2026.2.12 or later and rotate/review BlueBubbles webhook tokens configured on affected hosts.", []string{"cve", "openclaw", "package-json", "bluebubbles", "auth-bypass"})
}
func openclawACPAttachmentPathTraversalFinding(path, match string) finding.Finding {
	return openclawBacklogFinding(path, match, "openclaw-acp-attachment-path-traversal", finding.SeverityHigh, "OpenClaw before 2026.3.31 allows ACP attachment path traversal", "CVE-2026-41370: OpenClaw before 2026.3.31 accepts ACP dispatch attachment paths that can traverse outside the intended workspace, allowing arbitrary local file reads through agent attachment handling.", "Upgrade OpenClaw to 2026.3.31 or later and review ACP attachment history on affected hosts.", []string{"cve", "openclaw", "package-json", "acp", "path-traversal"})
}
func openclawJQEnvDisclosureFinding(path, match string) finding.Finding {
	return openclawBacklogFinding(path, match, "openclaw-jq-env-disclosure", finding.SeverityHigh, "OpenClaw before 2026.3.28 can disclose process environment through jq", "CVE-2026-41368: OpenClaw before 2026.3.28 allowed jq safe-bin expressions to access $ENV, exposing process environment variables to agent-controlled transformations.", "Upgrade OpenClaw to 2026.3.28 or later and rotate secrets present in vulnerable OpenClaw process environments.", []string{"cve", "openclaw", "package-json", "jq", "secrets"})
}
func openclawLocalMediaRootSelfWhitelistFinding(path, match string) finding.Finding {
	return openclawBacklogFinding(path, match, "openclaw-local-media-root-self-whitelist", finding.SeverityHigh, "OpenClaw before 2026.3.31 can self-whitelist local media roots", "CVE-2026-41366: OpenClaw before 2026.3.31 lets appendLocalMediaParentRoots expand local media parent roots, allowing model-initiated local file reads outside intended media allowlists.", "Upgrade OpenClaw to 2026.3.31 or later and review local media roots and file access logs from affected hosts.", []string{"cve", "openclaw", "package-json", "file-read", "media"})
}
func openclawDevicePairBootstrapScopeBypassFinding(path, match string) finding.Finding {
	return openclawBacklogFinding(path, match, "openclaw-device-pair-bootstrap-scope-bypass", finding.SeverityHigh, "OpenClaw before 2026.5.4 allows device-pair bootstrap scope bypass", "CVE-2026-32905: OpenClaw before 2026.5.4 lets non-owner authorized chat senders issue device-pairing bootstrap codes through the bundled device-pair plugin.", "Upgrade OpenClaw to 2026.5.4 or later and revoke device-pair bootstrap codes issued by vulnerable versions.", []string{"cve", "openclaw", "package-json", "device-pairing", "auth-bypass"})
}
func openclawSlackPluginApprovalGateBypassFinding(path, match string) finding.Finding {
	return openclawBacklogFinding(path, match, "openclaw-slack-plugin-approval-gate-bypass", finding.SeverityMedium, "OpenClaw before 2026.5.12 bypasses Slack plugin approval gates", "CVE-2026-32906: OpenClaw before 2026.5.12 allows exec-authorized Slack users to resolve plugin approvals through the wrong approval gate.", "Upgrade OpenClaw to 2026.5.12 or later and review Slack plugin approvals completed on vulnerable versions.", []string{"cve", "openclaw", "package-json", "slack", "approval-bypass"})
}
func openclawQQBotAdminPolicyBypassFinding(path, match string) finding.Finding {
	return openclawBacklogFinding(path, match, "openclaw-qqbot-admin-policy-bypass", finding.SeverityMedium, "OpenClaw before 2026.4.29 bypasses QQBot admin command policy", "CVE-2026-34507: OpenClaw before 2026.4.29 lets QQBot admin commands skip DM-only and allowFrom policy checks for authenticated senders.", "Upgrade OpenClaw to 2026.4.29 or later and review QQBot admin command usage on affected deployments.", []string{"cve", "openclaw", "package-json", "qqbot", "policy-bypass"})
}
func openclawQQBotApprovalButtonBypassFinding(path, match string) finding.Finding {
	return openclawBacklogFinding(path, match, "openclaw-qqbot-approval-button-bypass", finding.SeverityHigh, "OpenClaw before 2026.5.18 bypasses QQBot approval button identity checks", "CVE-2026-35630: OpenClaw before 2026.5.18 fails to enforce configured approver identity on QQBot native approval buttons.", "Upgrade OpenClaw to 2026.5.18 or later and review QQBot approval actions accepted by vulnerable versions.", []string{"cve", "openclaw", "package-json", "qqbot", "approval-bypass"})
}
func openclawBrowserTabSSRFReuseFinding(path, match string) finding.Finding {
	return openclawBacklogFinding(path, match, "openclaw-browser-tab-ssrf-reuse", finding.SeverityMedium, "OpenClaw before 2026.4.29 can reuse blocked browser tabs for SSRF", "CVE-2026-35673: OpenClaw before 2026.4.29 lets browser debug and export routes reuse already-open blocked tabs, bypassing SSRF policy boundaries.", "Upgrade OpenClaw to 2026.4.29 or later and review browser debug/export route exposure on affected hosts.", []string{"cve", "openclaw", "package-json", "browser", "ssrf"})
}
func openclawGatewayChatSendScopeBypassFinding(path, match string) finding.Finding {
	return openclawBacklogFinding(path, match, "openclaw-gateway-chat-send-scope-bypass", finding.SeverityHigh, "OpenClaw before 2026.5.18 bypasses Gateway chat.send scopes", "CVE-2026-35674: OpenClaw before 2026.5.18 lets scoped Gateway chat.send clients execute privileged commands and mutate plugin, config, MCP, allowlist, or ACP state.", "Upgrade OpenClaw to 2026.5.18 or later and review privileged state mutations performed through Gateway chat.send on affected deployments.", []string{"cve", "openclaw", "package-json", "gateway", "scope-bypass"})
}
func openclawNodePairingReconnectScopeConfusionFinding(path, match string) finding.Finding {
	return openclawBacklogFinding(path, match, "openclaw-node-pairing-reconnect-scope-confusion", finding.SeverityCritical, "OpenClaw before 2026.5.27 is vulnerable to node pairing reconnection scope confusion", "CVE-2026-53838: OpenClaw before 2026.5.27 can let paired nodes confuse approval scope decisions during reconnection, restoring or presenting broader node authority than intended.", "Upgrade OpenClaw to 2026.5.27 or later and review paired-node approvals and reconnection activity on affected deployments.", []string{"cve", "openclaw", "package-json", "node-pairing", "scope-confusion"})
}
func openclawShellOptionRevalidationBypassFinding(path, match string) finding.Finding {
	return openclawBacklogFinding(path, match, "openclaw-shell-option-revalidation-bypass", finding.SeverityHigh, "OpenClaw before 2026.5.12 is vulnerable to shell option revalidation bypass", "CVE-2026-53806: OpenClaw before 2026.5.12 can let combined POSIX shell flags bypass exec revalidation checks, allowing inline shell content to evade intended allowlist validation when the affected feature is enabled.", "Upgrade OpenClaw to 2026.5.12 or later and review exec allowlist decisions made on affected deployments.", []string{"cve", "openclaw", "package-json", "shell", "command-execution", "allowlist-bypass"})
}
func openclawTelegramCallbackAllowFromBypassFinding(path, match string) finding.Finding {
	return openclawBacklogFinding(path, match, "openclaw-telegram-callback-allowfrom-bypass", finding.SeverityHigh, "OpenClaw before 2026.5.6 is vulnerable to Telegram callback allowFrom bypass", "CVE-2026-53807: OpenClaw before 2026.5.6 lets Telegram interactive callbacks mark senders authorized before commands.allowFrom validation is enforced, allowing authenticated users to invoke command behavior outside configured sender restrictions.", "Upgrade OpenClaw to 2026.5.6 or later and review Telegram interactive callback activity on affected deployments.", []string{"cve", "openclaw", "package-json", "telegram", "auth-bypass"})
}
func openclawMarketplaceExtensionMetadataRedirectFinding(path, match string) finding.Finding {
	return openclawBacklogFinding(path, match, "openclaw-marketplace-extension-metadata-redirect", finding.SeverityHigh, "OpenClaw before 2026.5.18 can load runtime extensions from unscanned marketplace metadata targets", "CVE-2026-53810: OpenClaw before 2026.5.18 lets marketplace runtime extension metadata redirect loading toward unscanned package payloads, allowing trusted-operator extension metadata to bypass reviewed package entry points.", "Upgrade OpenClaw to 2026.5.18 or later and review marketplace/runtime extension metadata installed while vulnerable versions were in use.", []string{"cve", "openclaw", "package-json", "marketplace", "code-execution"})
}
func openclawMatrixAllowFromDisplayNameBypassFinding(path, match string) finding.Finding {
	return openclawBacklogFinding(path, match, "openclaw-matrix-allowfrom-displayname-bypass", finding.SeverityHigh, "OpenClaw before 2026.5.7 lets Matrix display names bypass allowFrom policy", "CVE-2026-53811: OpenClaw before 2026.5.7 lets authenticated Matrix accounts match allowFrom policy entries through mutable display names instead of stable sender identity, allowing account owners to escalate to policy-authorized Matrix control flows.", "Upgrade OpenClaw to 2026.5.7 or later and review Matrix allowFrom policy entries and command activity from vulnerable deployments.", []string{"cve", "openclaw", "dependency-manifest", "matrix", "allowfrom", "auth-bypass"})
}

func openclawBacklogFinding(path, match, ruleID string, severity finding.Severity, title, description, suggestedFix string, tags []string) finding.Finding {
	return finding.New(finding.Args{
		RuleID:       ruleID,
		Severity:     severity,
		Taxonomy:     finding.TaxDetectable,
		Title:        title,
		Description:  description,
		Path:         path,
		Match:        match,
		SuggestedFix: suggestedFix,
		Tags:         tags,
	})
}
