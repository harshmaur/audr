// Package builtin registers Audr's built-in rule corpus.
//
// Import this package for side effects (`_ "...internal/rules/builtin"`)
// so init() registers every rule with the global registry.
//
// File organization mirrors internal/parse/: one file per format-family.
// claude.go owns rules over Claude Code settings, codex.go owns Codex
// CLI rules, etc. mcp.go owns rules that operate over the normalized
// MCP server model and fire across .mcp.json + Codex TOML + Windsurf JSON.
package builtin

import (
	"github.com/harshmaur/audr/internal/rules"
)

func init() {
	for _, r := range builtins() {
		rules.Register(r)
	}
}

// builtins returns the rule list. Order doesn't affect runtime; rules are
// registered by ID. The list groups by format-family for readability.
//
// Stable contract: rule IDs do NOT change across releases. Adding a new
// rule appends to the appropriate group. Removing a rule is a breaking
// change and must be announced in CHANGELOG.
func builtins() []rules.Rule {
	return []rules.Rule{
		// MCP rules — fire across all MCP-bearing config formats.
		mcpUnpinnedNPX{},
		mcpProdSecretEnv{},
		mcpShellPipelineCommand{},
		mcpPlaintextAPIKey{},
		mcpDynamicConfigInjection{},
		mcpUnauthRemoteURL{},
		wiresharkMCPExportObjectsUnbounded{},
		nocturneMemoryMissingAPIToken{},
		mcpServerKubernetesToolFilterBypass{},
		mcpServerKubernetesKubectlFlagTokenExfil{},
		mcpServerKubernetesStructuredArgTokenExfil{},
		fastMCPTelegramBearerTokenPathTraversal{},
		chromeDevToolsMCPDaemonPidSymlink{},
		chromeDevToolsMCPRootsSymlinkEscape{},
		githubMCPServerLockdownGlobalCache{},
		kongKonnectMCPPromptInjection{},
		lineDesktopMCPUnauthHTTPMode{},
		deepseekMCPServerUnauthHTTP{},
		windowsMCPUnauthHTTPCORS{},
		mcpPinotUnauthHTTPDefault{},
		googleapisMCPToolboxWildcardOriginHost{},
		googleapisMCPToolboxLegacyProtocolScopeBypass{},
		networkAIMCPSSEEmptySecret{},
		awesomeMCPWikiSummarySSRF{},

		// Claude Code rules.
		claudeHookShellRCE{},
		claudeSkipPermissionPrompt{},
		claudeMCPAutoApprove{},
		claudeBashAllowlistTooBroad{},
		claudeThirdPartyPluginEnabled{},

		// Codex CLI rules.
		codexApprovalDisabled{},
		codexTrustHomeOrBroad{},

		// Cursor permissions.json rules.
		cursorAllowlistTooBroad{},
		cursorMCPWildcard{},
		cursorWorkspaceEscapingSymlinkCVE202650549{},

		// Skill (markdown) rules.
		skillShellHijack{},
		skillUndeclaredDangerousTool{},

		// GitHub Actions rules.
		ghaWriteAllPermissions{},
		ghaSecretsInAgentStep{},
		ghaBase64SecretExfilWorkflow{},
		ghaClaudeIssueAgentInjection{},
		miniShaiHuludWorkflowSecretExfil{},

		// Shell rc rules.
		shellrcSecretExport{},

		// PowerShell profile rules — same family runs against profile
		// scripts and PSReadLine ConsoleHost_history.
		powershellIWRIEX{},
		powershellSecretEnv{},
		powershellExecutionPolicyBypass{},

		// Dependency CVE coverage is delegated to external OSV-Scanner unless
		// OSV lacks coverage for a locally auditable agent/MCP package surface.
		microsoftAPMPluginComponentTraversal{},
		mlflowAssistantOriginBypass{},
		deeptutorMCPToolGrantBypass{},
		deepseekMCPSessionIDHijack{},
		mcpCalculateServerEvalRCE{},
		lumiverseMCPArgsRCE{},
		gitlabMCPServerUnauthHTTP{},
		codeRunnerMCPServerUnauthHTTP{},
		libreChatMCPEnvSecretLeak{},
		libreChatMCPAdminSecretResponseLeak{},
		libreChatMCPOAuthResourceConfusion{},
		presentonMCPAuthBypass{},
		flowiseCustomMCPMissingAuth{},
		flowiseCustomMCPEnvCaseBypass{},
		serenaDashboardUnauthFlaskAPI{},
		clineDashboardBrowserOriginBypass{},
		rufloMCPBridgeUnauthRCE{},
		rtkRewriteOpenClawExecSyncInjection{},
		rtkPermissionSplitterShellBoundaryBypass{},
		xhsMCPMediaPathsSSRF{},
		directusMCPFileURLSSRF{},
		cloudbaseMCPOpenURLSSRF{},
		mcpChatStudioModelsBaseURLSSRF{},
		mcpURLDownloaderValidateURLSafeSSRF{},
		aiderMCPServerRelativeEditableFilesCommandInjection{},
		mcpDataVisWebScraperSSRF{},
		clineMCPMemoryBankInitializePathTraversal{},
		anythingLLMFilesystemRGOptionInjection{},
		mcpilotServerBaseURLSSRF{},
		junoClawPluginShellRawBlocklistBypass{},
		junoClawPluginShellShCAgentCommand{},
		hermesAgentSkillsGuardMultiwordPatterns{},
		libreChatAPIKeysUserIDIDOR{},
		aiderMCPWorkingDirEditableFilesCommandInjection{},
		aerostackMCPWhatsAppMediaURLSSRF{},
		angularLanguageServiceTrustedMarkdownCommandURI{},
		claudeCodeWorktreeGitConfusion{},
		claudeHUDComspecCommandInjection{},
		claudeHUDOSC8TerminalInjection{},
		miniShaiHuludMaliciousOptionalDependency{},
		miniShaiHuludClaudePersistence{},
		miniShaiHuludVSCodePersistence{},
		miniShaiHuludTokenMonitorPersistence{},
		miniShaiHuludDroppedPayload{},
		miniShaiHuludStage6GitHubC2IOC{},

		// Git config rules for nested bare repositories and executable helpers.
		copilotCLINestedGitConfigExec{},

		// Dependency supply-chain hardening rules.
		dependencyMinimumReleaseAgeMissing{},
		pnpmLockfileMissingIntegrity{},
		pnpmUnscopedAuthTokenRegistryForwarding{},
		miseHTTPBackendSymlinkEscape{},
		vLLMFlashInferDependencyConfusion{},

		// package.json OpenClaw version posture rules.
		openclawUnboundBootstrapSetupCode{},
		openclawConfigPatchConsentBypass{},
		openclawWebsocketUpgradeExhaustion{},
		openclawNodePairApproveScopeBypass{},
		openclawPluginAuthOperatorWriteBypass{},
		openclawNodeEventToolAccess{},
		openclawTeamsWebhookPreauthBodyDos{},
		openclawTrustedProxyScopeClearing{},
		openclawBundledHooksEnvOverride{},
		openclawBundledPluginsEnvOverride{},
		openclawHeartbeatOwnerDowngrade{},
		openclawTrustedHookMetadataInjection{},
		openclawFeishuWebhookAuthBypass{},
		openclawBearerSecretRefRotationBypass{},
		openclawSandboxCDPRelayPublicBind{},
		openclawAsyncExecCompletionOwnerDowngrade{},
		openclawDeviceTokenRoleMinting{},
		openclawMatrixDMPairingAuthBypass{},
		openclawBlueBubblesWebhookAuthBypass{},
		openclawACPAttachmentPathTraversal{},
		openclawJQEnvDisclosure{},
		openclawLocalMediaRootSelfWhitelist{},
		openclawDevicePairBootstrapScopeBypass{},
		openclawSlackPluginApprovalGateBypass{},
		openclawQQBotAdminPolicyBypass{},
		openclawQQBotStreamingConfigBypass{},
		openclawQQBotApprovalButtonBypass{},
		openclawBrowserTabSSRFReuse{},
		openclawGatewayChatSendScopeBypass{},
		openclawSystemRunSafeBinShellExpansion{},
		openclawNativeCommandOwnerOnlyBypass{},
		openclawNodePairingReconnectScopeConfusion{},
		openclawShellOptionRevalidationBypass{},
		openclawPowerShellEncodedCommandAliasBypass{},
		openclawTelegramCallbackAllowFromBypass{},
		openclawMarketplaceExtensionMetadataRedirect{},
		openclawWebsocketOperatorScopeBypass{},
		openclawShellWrapperArgvMutation{},
		openclawMatrixAllowFromDisplayNameBypass{},
		openclawSlackAllowFromDisplayNameBypass{},
		openclawBrowserControlPrivateNetworkSSRF{},
		openclawMemoryCoreArtifactRootTraversal{},
		openclawHookTriggeredOwnerLoopbackEscalation{},
		openclawNodeEventProvenanceForgery{},
		openclawControlUIPairingLocalitySpoof{},
		openclawSkillInstallHomebrewEnvOverride{},
		openclawApprovalDisplayTruncation{},
		openclawTrustedProxyIdentityHeaderForgery{},
		openclawRetryEndpointHostnamePrefixBypass{},
		openclawWorkspaceDotenvCredentialOverride{},
	}
}
