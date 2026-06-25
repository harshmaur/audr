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
type openclawSystemRunSafeBinShellExpansion struct{}
type openclawNativeCommandOwnerOnlyBypass struct{}
type openclawNodePairingReconnectScopeConfusion struct{}
type openclawShellOptionRevalidationBypass struct{}
type openclawPowerShellEncodedCommandAliasBypass struct{}
type openclawTelegramCallbackAllowFromBypass struct{}
type openclawMarketplaceExtensionMetadataRedirect struct{}
type openclawWebsocketOperatorScopeBypass struct{}
type openclawShellWrapperArgvMutation struct{}
type openclawMatrixAllowFromDisplayNameBypass struct{}
type openclawSlackAllowFromDisplayNameBypass struct{}
type openclawBrowserControlPrivateNetworkSSRF struct{}
type openclawMemoryCoreArtifactRootTraversal struct{}
type openclawHookTriggeredOwnerLoopbackEscalation struct{}
type openclawNodeEventProvenanceForgery struct{}
type openclawControlUIPairingLocalitySpoof struct{}
type openclawSkillInstallHomebrewEnvOverride struct{}
type openclawApprovalDisplayTruncation struct{}

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

func (openclawSystemRunSafeBinShellExpansion) ID() string {
	return "openclaw-system-run-safebin-shell-expansion"
}
func (openclawSystemRunSafeBinShellExpansion) Title() string {
	return "OpenClaw version is vulnerable to system.run safe-bin shell expansion"
}
func (openclawSystemRunSafeBinShellExpansion) Severity() finding.Severity {
	return finding.SeverityHigh
}
func (openclawSystemRunSafeBinShellExpansion) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (openclawSystemRunSafeBinShellExpansion) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest, parse.FormatPackageJSON}
}
func (openclawSystemRunSafeBinShellExpansion) Apply(doc *parse.Document) []finding.Finding {
	return openclawPackageVersionFindings(doc, vulnerableOpenClawSystemRunSafeBinShellExpansionVersion, openclawSystemRunSafeBinShellExpansionFinding)
}

func (openclawNativeCommandOwnerOnlyBypass) ID() string {
	return "openclaw-native-command-owner-only-bypass"
}
func (openclawNativeCommandOwnerOnlyBypass) Title() string {
	return "OpenClaw version is vulnerable to native command owner-only bypass"
}
func (openclawNativeCommandOwnerOnlyBypass) Severity() finding.Severity {
	return finding.SeverityHigh
}
func (openclawNativeCommandOwnerOnlyBypass) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (openclawNativeCommandOwnerOnlyBypass) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest, parse.FormatPackageJSON}
}
func (openclawNativeCommandOwnerOnlyBypass) Apply(doc *parse.Document) []finding.Finding {
	return openclawPackageVersionFindings(doc, vulnerableOpenClawNativeCommandOwnerOnlyBypassVersion, openclawNativeCommandOwnerOnlyBypassFinding)
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

func (openclawPowerShellEncodedCommandAliasBypass) ID() string {
	return "openclaw-powershell-encoded-command-alias-bypass"
}
func (openclawPowerShellEncodedCommandAliasBypass) Title() string {
	return "OpenClaw version is vulnerable to PowerShell encoded-command alias bypass"
}
func (openclawPowerShellEncodedCommandAliasBypass) Severity() finding.Severity {
	return finding.SeverityHigh
}
func (openclawPowerShellEncodedCommandAliasBypass) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (openclawPowerShellEncodedCommandAliasBypass) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest, parse.FormatPackageJSON}
}
func (openclawPowerShellEncodedCommandAliasBypass) Apply(doc *parse.Document) []finding.Finding {
	return openclawPackageVersionFindings(doc, vulnerableOpenClawPowerShellEncodedCommandAliasBypassVersion, openclawPowerShellEncodedCommandAliasBypassFinding)
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

func (openclawWebsocketOperatorScopeBypass) ID() string {
	return "openclaw-websocket-operator-scope-bypass"
}
func (openclawWebsocketOperatorScopeBypass) Title() string {
	return "OpenClaw version is vulnerable to WebSocket operator scope bypass"
}
func (openclawWebsocketOperatorScopeBypass) Severity() finding.Severity {
	return finding.SeverityHigh
}
func (openclawWebsocketOperatorScopeBypass) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (openclawWebsocketOperatorScopeBypass) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest, parse.FormatPackageJSON}
}
func (openclawWebsocketOperatorScopeBypass) Apply(doc *parse.Document) []finding.Finding {
	return openclawPackageVersionFindings(doc, vulnerableOpenClawWebsocketOperatorScopeBypassVersion, openclawWebsocketOperatorScopeBypassFinding)
}

func (openclawShellWrapperArgvMutation) ID() string {
	return "openclaw-shell-wrapper-argv-mutation"
}
func (openclawShellWrapperArgvMutation) Title() string {
	return "OpenClaw version is vulnerable to shell wrapper argv mutation after approval"
}
func (openclawShellWrapperArgvMutation) Severity() finding.Severity {
	return finding.SeverityHigh
}
func (openclawShellWrapperArgvMutation) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (openclawShellWrapperArgvMutation) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest, parse.FormatPackageJSON}
}
func (openclawShellWrapperArgvMutation) Apply(doc *parse.Document) []finding.Finding {
	return openclawPackageVersionFindings(doc, vulnerableOpenClawShellWrapperArgvMutationVersion, openclawShellWrapperArgvMutationFinding)
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

func (openclawSlackAllowFromDisplayNameBypass) ID() string {
	return "openclaw-slack-allowfrom-displayname-bypass"
}
func (openclawSlackAllowFromDisplayNameBypass) Title() string {
	return "OpenClaw version is vulnerable to Slack allowFrom display-name bypass"
}
func (openclawSlackAllowFromDisplayNameBypass) Severity() finding.Severity {
	return finding.SeverityHigh
}
func (openclawSlackAllowFromDisplayNameBypass) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (openclawSlackAllowFromDisplayNameBypass) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest, parse.FormatPackageJSON}
}
func (openclawSlackAllowFromDisplayNameBypass) Apply(doc *parse.Document) []finding.Finding {
	return openclawPackageVersionFindings(doc, vulnerableOpenClawSlackAllowFromDisplayNameBypassVersion, openclawSlackAllowFromDisplayNameBypassFinding)
}

func (openclawBrowserControlPrivateNetworkSSRF) ID() string {
	return "openclaw-browser-control-private-network-ssrf"
}
func (openclawBrowserControlPrivateNetworkSSRF) Title() string {
	return "OpenClaw version is vulnerable to browser-control private-network SSRF"
}
func (openclawBrowserControlPrivateNetworkSSRF) Severity() finding.Severity {
	return finding.SeverityHigh
}
func (openclawBrowserControlPrivateNetworkSSRF) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (openclawBrowserControlPrivateNetworkSSRF) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest, parse.FormatPackageJSON}
}
func (openclawBrowserControlPrivateNetworkSSRF) Apply(doc *parse.Document) []finding.Finding {
	return openclawPackageVersionFindings(doc, vulnerableOpenClawBrowserControlPrivateNetworkSSRFVersion, openclawBrowserControlPrivateNetworkSSRFFinding)
}

func (openclawMemoryCoreArtifactRootTraversal) ID() string {
	return "openclaw-memory-core-artifact-root-traversal"
}
func (openclawMemoryCoreArtifactRootTraversal) Title() string {
	return "OpenClaw version is vulnerable to memory-core artifact root traversal"
}
func (openclawMemoryCoreArtifactRootTraversal) Severity() finding.Severity {
	return finding.SeverityHigh
}
func (openclawMemoryCoreArtifactRootTraversal) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (openclawMemoryCoreArtifactRootTraversal) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest, parse.FormatPackageJSON}
}
func (openclawMemoryCoreArtifactRootTraversal) Apply(doc *parse.Document) []finding.Finding {
	return openclawPackageVersionFindings(doc, vulnerableOpenClawMemoryCoreArtifactRootTraversalVersion, openclawMemoryCoreArtifactRootTraversalFinding)
}

func (openclawHookTriggeredOwnerLoopbackEscalation) ID() string {
	return "openclaw-hook-triggered-owner-loopback-escalation"
}
func (openclawHookTriggeredOwnerLoopbackEscalation) Title() string {
	return "OpenClaw version is vulnerable to hook-triggered owner loopback escalation"
}
func (openclawHookTriggeredOwnerLoopbackEscalation) Severity() finding.Severity {
	return finding.SeverityHigh
}
func (openclawHookTriggeredOwnerLoopbackEscalation) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (openclawHookTriggeredOwnerLoopbackEscalation) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest, parse.FormatPackageJSON}
}
func (openclawHookTriggeredOwnerLoopbackEscalation) Apply(doc *parse.Document) []finding.Finding {
	return openclawPackageVersionFindings(doc, vulnerableOpenClawHookTriggeredOwnerLoopbackEscalationVersion, openclawHookTriggeredOwnerLoopbackEscalationFinding)
}

func (openclawNodeEventProvenanceForgery) ID() string {
	return "openclaw-node-event-provenance-forgery"
}
func (openclawNodeEventProvenanceForgery) Title() string {
	return "OpenClaw version is vulnerable to node event provenance forgery"
}
func (openclawNodeEventProvenanceForgery) Severity() finding.Severity {
	return finding.SeverityHigh
}
func (openclawNodeEventProvenanceForgery) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (openclawNodeEventProvenanceForgery) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest, parse.FormatPackageJSON}
}
func (openclawNodeEventProvenanceForgery) Apply(doc *parse.Document) []finding.Finding {
	return openclawPackageVersionFindings(doc, vulnerableOpenClawNodeEventProvenanceForgeryVersion, openclawNodeEventProvenanceForgeryFinding)
}

func (openclawControlUIPairingLocalitySpoof) ID() string {
	return "openclaw-control-ui-pairing-locality-spoof"
}
func (openclawControlUIPairingLocalitySpoof) Title() string {
	return "OpenClaw version is vulnerable to Control UI pairing locality spoofing"
}
func (openclawControlUIPairingLocalitySpoof) Severity() finding.Severity {
	return finding.SeverityHigh
}
func (openclawControlUIPairingLocalitySpoof) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (openclawControlUIPairingLocalitySpoof) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest, parse.FormatPackageJSON}
}
func (openclawControlUIPairingLocalitySpoof) Apply(doc *parse.Document) []finding.Finding {
	return openclawPackageVersionFindings(doc, vulnerableOpenClawControlUIPairingLocalitySpoofVersion, openclawControlUIPairingLocalitySpoofFinding)
}

func (openclawSkillInstallHomebrewEnvOverride) ID() string {
	return "openclaw-skill-install-homebrew-env-override"
}
func (openclawSkillInstallHomebrewEnvOverride) Title() string {
	return "OpenClaw version is vulnerable to skill install Homebrew executable override"
}
func (openclawSkillInstallHomebrewEnvOverride) Severity() finding.Severity {
	return finding.SeverityHigh
}
func (openclawSkillInstallHomebrewEnvOverride) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (openclawSkillInstallHomebrewEnvOverride) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest, parse.FormatPackageJSON}
}
func (openclawSkillInstallHomebrewEnvOverride) Apply(doc *parse.Document) []finding.Finding {
	return openclawPackageVersionFindings(doc, vulnerableOpenClawSkillInstallHomebrewEnvOverrideVersion, openclawSkillInstallHomebrewEnvOverrideFinding)
}

func (openclawApprovalDisplayTruncation) ID() string {
	return "openclaw-approval-display-truncation"
}
func (openclawApprovalDisplayTruncation) Title() string {
	return "OpenClaw version is vulnerable to approval display truncation"
}
func (openclawApprovalDisplayTruncation) Severity() finding.Severity {
	return finding.SeverityHigh
}
func (openclawApprovalDisplayTruncation) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (openclawApprovalDisplayTruncation) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest, parse.FormatPackageJSON}
}
func (openclawApprovalDisplayTruncation) Apply(doc *parse.Document) []finding.Finding {
	return openclawPackageVersionFindings(doc, vulnerableOpenClawApprovalDisplayTruncationVersion, openclawApprovalDisplayTruncationFinding)
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
func vulnerableOpenClawSystemRunSafeBinShellExpansionVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 5, 18})
}
func vulnerableOpenClawNativeCommandOwnerOnlyBypassVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 5, 6})
}
func vulnerableOpenClawNodePairingReconnectScopeConfusionVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 5, 27})
}
func vulnerableOpenClawShellOptionRevalidationBypassVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 5, 12})
}
func vulnerableOpenClawPowerShellEncodedCommandAliasBypassVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 5, 12})
}
func vulnerableOpenClawTelegramCallbackAllowFromBypassVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 5, 6})
}
func vulnerableOpenClawMarketplaceExtensionMetadataRedirectVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 5, 18})
}
func vulnerableOpenClawWebsocketOperatorScopeBypassVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 5, 18})
}
func vulnerableOpenClawShellWrapperArgvMutationVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 5, 18})
}
func vulnerableOpenClawMatrixAllowFromDisplayNameBypassVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 5, 7})
}
func vulnerableOpenClawSlackAllowFromDisplayNameBypassVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 5, 3})
}
func vulnerableOpenClawBrowserControlPrivateNetworkSSRFVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 5, 18})
}
func vulnerableOpenClawMemoryCoreArtifactRootTraversalVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 4, 25})
}
func vulnerableOpenClawHookTriggeredOwnerLoopbackEscalationVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 5, 20})
}
func vulnerableOpenClawNodeEventProvenanceForgeryVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 5, 18})
}
func vulnerableOpenClawControlUIPairingLocalitySpoofVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 5, 22})
}
func vulnerableOpenClawSkillInstallHomebrewEnvOverrideVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 5, 27})
}
func vulnerableOpenClawApprovalDisplayTruncationVersion(raw string) bool {
	return vulnerableOpenClawVersionBefore(raw, []int{2026, 5, 18})
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
func openclawSystemRunSafeBinShellExpansionFinding(path, match string) finding.Finding {
	return openclawBacklogFinding(path, match, "openclaw-system-run-safebin-shell-expansion", finding.SeverityHigh, "OpenClaw before 2026.5.18 lets shell expansion modify system.run safe-bin command interpretation", "CVE-2026-53831: OpenClaw before 2026.5.18 can allow POSIX shell metacharacters in approved system.run safe-bin commands to alter command interpretation and read unintended node-local files or sensitive configuration data.", "Upgrade OpenClaw to 2026.5.18 or later and review system.run safe-bin allowlist approvals and node-local file access from affected deployments.", []string{"cve", "openclaw", "dependency-manifest", "system-run", "shell", "file-read", "allowlist-bypass"})
}
func openclawNativeCommandOwnerOnlyBypassFinding(path, match string) finding.Finding {
	return openclawBacklogFinding(path, match, "openclaw-native-command-owner-only-bypass", finding.SeverityHigh, "OpenClaw before 2026.5.6 allows native command owner-only bypass", "CVE-2026-53828: OpenClaw before 2026.5.6 lets authenticated senders trigger native command handling without enforcing owner-only command policy, allowing unauthorized users to reach privileged native commands.", "Upgrade OpenClaw to 2026.5.6 or later and review native command execution activity from unauthorized senders on affected deployments.", []string{"cve", "openclaw", "dependency-manifest", "native-command", "auth-bypass"})
}
func openclawNodePairingReconnectScopeConfusionFinding(path, match string) finding.Finding {
	return openclawBacklogFinding(path, match, "openclaw-node-pairing-reconnect-scope-confusion", finding.SeverityCritical, "OpenClaw before 2026.5.27 is vulnerable to node pairing reconnection scope confusion", "CVE-2026-53838: OpenClaw before 2026.5.27 can let paired nodes confuse approval scope decisions during reconnection, restoring or presenting broader node authority than intended.", "Upgrade OpenClaw to 2026.5.27 or later and review paired-node approvals and reconnection activity on affected deployments.", []string{"cve", "openclaw", "package-json", "node-pairing", "scope-confusion"})
}
func openclawShellOptionRevalidationBypassFinding(path, match string) finding.Finding {
	return openclawBacklogFinding(path, match, "openclaw-shell-option-revalidation-bypass", finding.SeverityHigh, "OpenClaw before 2026.5.12 is vulnerable to shell option revalidation bypass", "CVE-2026-53806: OpenClaw before 2026.5.12 can let combined POSIX shell flags bypass exec revalidation checks, allowing inline shell content to evade intended allowlist validation when the affected feature is enabled.", "Upgrade OpenClaw to 2026.5.12 or later and review exec allowlist decisions made on affected deployments.", []string{"cve", "openclaw", "package-json", "shell", "command-execution", "allowlist-bypass"})
}
func openclawPowerShellEncodedCommandAliasBypassFinding(path, match string) finding.Finding {
	return openclawBacklogFinding(path, match, "openclaw-powershell-encoded-command-alias-bypass", finding.SeverityHigh, "OpenClaw before 2026.5.12 allows PowerShell encoded-command alias bypass", "CVE-2026-53836: OpenClaw before 2026.5.12 does not recognize abbreviated PowerShell encoded-command flag aliases in its allowlist parser, letting authenticated operators execute encoded PowerShell content outside intended command policy.", "Upgrade OpenClaw to 2026.5.12 or later and review PowerShell command executions allowed by vulnerable OpenClaw deployments.", []string{"cve", "openclaw", "dependency-manifest", "powershell", "command-execution", "allowlist-bypass"})
}
func openclawTelegramCallbackAllowFromBypassFinding(path, match string) finding.Finding {
	return openclawBacklogFinding(path, match, "openclaw-telegram-callback-allowfrom-bypass", finding.SeverityHigh, "OpenClaw before 2026.5.6 is vulnerable to Telegram callback allowFrom bypass", "CVE-2026-53807: OpenClaw before 2026.5.6 lets Telegram interactive callbacks mark senders authorized before commands.allowFrom validation is enforced, allowing authenticated users to invoke command behavior outside configured sender restrictions.", "Upgrade OpenClaw to 2026.5.6 or later and review Telegram interactive callback activity on affected deployments.", []string{"cve", "openclaw", "package-json", "telegram", "auth-bypass"})
}
func openclawMarketplaceExtensionMetadataRedirectFinding(path, match string) finding.Finding {
	return openclawBacklogFinding(path, match, "openclaw-marketplace-extension-metadata-redirect", finding.SeverityHigh, "OpenClaw before 2026.5.18 can load runtime extensions from unscanned marketplace metadata targets", "CVE-2026-53810: OpenClaw before 2026.5.18 lets marketplace runtime extension metadata redirect loading toward unscanned package payloads, allowing trusted-operator extension metadata to bypass reviewed package entry points.", "Upgrade OpenClaw to 2026.5.18 or later and review marketplace/runtime extension metadata installed while vulnerable versions were in use.", []string{"cve", "openclaw", "package-json", "marketplace", "code-execution"})
}
func openclawWebsocketOperatorScopeBypassFinding(path, match string) finding.Finding {
	return openclawBacklogFinding(path, match, "openclaw-websocket-operator-scope-bypass", finding.SeverityHigh, "OpenClaw before 2026.5.18 accepts client-declared WebSocket operator scopes", "CVE-2026-53821: OpenClaw before 2026.5.18 accepted WebSocket client-declared operator scopes before binding them to server-approved pairing or trusted-proxy authorization, allowing restricted Control UI clients to obtain operator.admin authority.", "Upgrade OpenClaw to 2026.5.18 or later and review Control UI WebSocket sessions and admin-gated Gateway RPC activity on affected deployments.", []string{"cve", "openclaw", "dependency-manifest", "websocket", "control-ui", "auth-bypass"})
}
func openclawShellWrapperArgvMutationFinding(path, match string) finding.Finding {
	return openclawBacklogFinding(path, match, "openclaw-shell-wrapper-argv-mutation", finding.SeverityHigh, "OpenClaw before 2026.5.18 lets shell wrapper argv change after approval", "CVE-2026-53822: OpenClaw before 2026.5.18 can rebuild shell wrapper command arguments after allowlist approval, letting authenticated operators hide unapproved suffixes and execute unintended commands.", "Upgrade OpenClaw to 2026.5.18 or later and review shell wrapper approvals and command executions made on affected deployments.", []string{"cve", "openclaw", "dependency-manifest", "shell", "command-execution", "approval-bypass"})
}
func openclawMatrixAllowFromDisplayNameBypassFinding(path, match string) finding.Finding {
	return openclawBacklogFinding(path, match, "openclaw-matrix-allowfrom-displayname-bypass", finding.SeverityHigh, "OpenClaw before 2026.5.7 lets Matrix display names bypass allowFrom policy", "CVE-2026-53811: OpenClaw before 2026.5.7 lets authenticated Matrix accounts match allowFrom policy entries through mutable display names instead of stable sender identity, allowing account owners to escalate to policy-authorized Matrix control flows.", "Upgrade OpenClaw to 2026.5.7 or later and review Matrix allowFrom policy entries and command activity from vulnerable deployments.", []string{"cve", "openclaw", "dependency-manifest", "matrix", "allowfrom", "auth-bypass"})
}
func openclawSlackAllowFromDisplayNameBypassFinding(path, match string) finding.Finding {
	return openclawBacklogFinding(path, match, "openclaw-slack-allowfrom-displayname-bypass", finding.SeverityHigh, "OpenClaw before 2026.5.3 lets Slack display names bypass allowFrom policy", "CVE-2026-53823: OpenClaw before 2026.5.3 binds Slack allowFrom checks to mutable display-name metadata, allowing Slack users who can change display names to match policy entries and gain unintended agent access.", "Upgrade OpenClaw to 2026.5.3 or later and review Slack allowFrom policy entries and command activity from vulnerable deployments.", []string{"cve", "openclaw", "dependency-manifest", "slack", "allowfrom", "auth-bypass"})
}
func openclawBrowserControlPrivateNetworkSSRFFinding(path, match string) finding.Finding {
	return openclawBacklogFinding(path, match, "openclaw-browser-control-private-network-ssrf", finding.SeverityHigh, "OpenClaw before 2026.5.18 can bypass private-network navigation blocks in browser control", "CVE-2026-53812: OpenClaw before 2026.5.18 contains a browser-control server-side request forgery flaw that lets authenticated users bypass private-network navigation restrictions after redirects.", "Upgrade OpenClaw to 2026.5.18 or later and review browser-control navigation/export activity from vulnerable deployments.", []string{"cve", "openclaw", "dependency-manifest", "browser-control", "ssrf"})
}
func openclawMemoryCoreArtifactRootTraversalFinding(path, match string) finding.Finding {
	return openclawBacklogFinding(path, match, "openclaw-memory-core-artifact-root-traversal", finding.SeverityHigh, "OpenClaw before 2026.4.25 can load memory-core artifacts from unintended roots", "CVE-2026-53813: OpenClaw before 2026.4.25 lets workspace-controlled memory-core artifact root resolution traverse to unintended local package roots, potentially loading malicious artifacts from outside the intended workspace boundary.", "Upgrade OpenClaw to 2026.4.25 or later and review memory-core artifact roots and workspace state created by vulnerable versions.", []string{"cve", "openclaw", "dependency-manifest", "memory-core", "path-traversal"})
}
func openclawHookTriggeredOwnerLoopbackEscalationFinding(path, match string) finding.Finding {
	return openclawBacklogFinding(path, match, "openclaw-hook-triggered-owner-loopback-escalation", finding.SeverityHigh, "OpenClaw before 2026.5.20 can escalate hook-triggered runs to owner MCP loopback scope", "CVE-2026-53814: OpenClaw before 2026.5.20 incorrectly gives hook-triggered agent runs owner-scoped MCP loopback access, letting lower-trust hook input reach privileged local MCP tools.", "Upgrade OpenClaw to 2026.5.20 or later and review hook-triggered agent runs and local MCP tool activity on affected deployments.", []string{"cve", "openclaw", "dependency-manifest", "hooks", "mcp", "privilege-escalation"})
}
func openclawNodeEventProvenanceForgeryFinding(path, match string) finding.Finding {
	return openclawBacklogFinding(path, match, "openclaw-node-event-provenance-forgery", finding.SeverityHigh, "OpenClaw before 2026.5.18 can accept forged node exec lifecycle events", "CVE-2026-53816: OpenClaw before 2026.5.18 does not sufficiently validate node event provenance, letting paired or compromised nodes forge exec lifecycle events without system.run authorization.", "Upgrade OpenClaw to 2026.5.18 or later and review paired-node exec lifecycle activity from affected deployments.", []string{"cve", "openclaw", "dependency-manifest", "node-events", "provenance", "auth-bypass"})
}

func openclawControlUIPairingLocalitySpoofFinding(path, match string) finding.Finding {
	return openclawBacklogFinding(path, match, "openclaw-control-ui-pairing-locality-spoof", finding.SeverityHigh, "OpenClaw before 2026.5.22 can accept spoofed Control UI pairing locality", "CVE-2026-53817: OpenClaw before 2026.5.22 trusts spoofable locality information during Control UI pairing, allowing network-adjacent attackers to present non-local control flows as local and reach higher-trust agent-control actions.", "Upgrade OpenClaw to 2026.5.22 or later and review Control UI pairings created or re-authorized while vulnerable versions were in use.", []string{"cve", "openclaw", "dependency-manifest", "control-ui", "pairing", "auth-bypass"})
}

func openclawSkillInstallHomebrewEnvOverrideFinding(path, match string) finding.Finding {
	return openclawBacklogFinding(path, match, "openclaw-skill-install-homebrew-env-override", finding.SeverityHigh, "OpenClaw before 2026.5.27 lets workspace .env override Homebrew executable selection during skill install", "CVE-2026-53819: OpenClaw before 2026.5.27 contains an arbitrary code execution vulnerability in skill install flows where workspace .env files can override Homebrew executable selection, allowing trusted-workspace attackers to execute unintended Homebrew-compatible executables during skill setup.", "Upgrade OpenClaw to 2026.5.27 or later and review skill setup activity and workspace .env files used by vulnerable versions.", []string{"cve", "openclaw", "dependency-manifest", "skill-install", "homebrew", "command-execution"})
}

func openclawApprovalDisplayTruncationFinding(path, match string) finding.Finding {
	return openclawBacklogFinding(path, match, "openclaw-approval-display-truncation", finding.SeverityHigh, "OpenClaw before 2026.5.18 can truncate approval displays", "CVE-2026-53829: OpenClaw before 2026.5.18 contains an approval display truncation flaw that can hide command suffixes or privileged action details from the user-facing approval prompt.", "Upgrade OpenClaw to 2026.5.18 or later and review approvals and command executions accepted on affected deployments.", []string{"cve", "openclaw", "dependency-manifest", "approval-bypass", "ui-truncation"})
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
