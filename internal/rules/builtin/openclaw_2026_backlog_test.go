package builtin

import (
	"testing"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

func TestOpenClaw2026BacklogRules_FlagVulnerablePackageAndAllowFixed(t *testing.T) {
	tests := []struct {
		name       string
		ruleID     string
		vulnerable string
		fixed      string
		apply      func(*parse.Document) []finding.Finding
	}{
		{"matrix dm pairing", "openclaw-matrix-dm-pairing-auth-bypass", "2026.4.14", "2026.4.15", func(d *parse.Document) []finding.Finding { return (openclawMatrixDMPairingAuthBypass{}).Apply(d) }},
		{"bluebubbles webhook", "openclaw-bluebubbles-webhook-auth-bypass", "2026.2.11", "2026.2.12", func(d *parse.Document) []finding.Finding { return (openclawBlueBubblesWebhookAuthBypass{}).Apply(d) }},
		{"acp attachment", "openclaw-acp-attachment-path-traversal", "2026.3.30", "2026.3.31", func(d *parse.Document) []finding.Finding { return (openclawACPAttachmentPathTraversal{}).Apply(d) }},
		{"jq env", "openclaw-jq-env-disclosure", "2026.3.27", "2026.3.28", func(d *parse.Document) []finding.Finding { return (openclawJQEnvDisclosure{}).Apply(d) }},
		{"local media root", "openclaw-local-media-root-self-whitelist", "2026.3.30", "2026.3.31", func(d *parse.Document) []finding.Finding { return (openclawLocalMediaRootSelfWhitelist{}).Apply(d) }},
		{"device pair", "openclaw-device-pair-bootstrap-scope-bypass", "2026.5.3", "2026.5.4", func(d *parse.Document) []finding.Finding { return (openclawDevicePairBootstrapScopeBypass{}).Apply(d) }},
		{"slack plugin", "openclaw-slack-plugin-approval-gate-bypass", "2026.5.11", "2026.5.12", func(d *parse.Document) []finding.Finding { return (openclawSlackPluginApprovalGateBypass{}).Apply(d) }},
		{"qqbot admin", "openclaw-qqbot-admin-policy-bypass", "2026.4.28", "2026.4.29", func(d *parse.Document) []finding.Finding { return (openclawQQBotAdminPolicyBypass{}).Apply(d) }},
		{"qqbot approval", "openclaw-qqbot-approval-button-bypass", "2026.5.17", "2026.5.18", func(d *parse.Document) []finding.Finding { return (openclawQQBotApprovalButtonBypass{}).Apply(d) }},
		{"browser ssrf", "openclaw-browser-tab-ssrf-reuse", "2026.4.28", "2026.4.29", func(d *parse.Document) []finding.Finding { return (openclawBrowserTabSSRFReuse{}).Apply(d) }},
		{"gateway chat", "openclaw-gateway-chat-send-scope-bypass", "2026.5.17", "2026.5.18", func(d *parse.Document) []finding.Finding {
			return (openclawGatewayChatSendScopeBypass{}).Apply(d)
		}},
		{"system.run safe-bin shell expansion", "openclaw-system-run-safebin-shell-expansion", "2026.5.17", "2026.5.18", func(d *parse.Document) []finding.Finding {
			return (openclawSystemRunSafeBinShellExpansion{}).Apply(d)
		}},
		{"native command owner-only", "openclaw-native-command-owner-only-bypass", "2026.5.5", "2026.5.6", func(d *parse.Document) []finding.Finding {
			return (openclawNativeCommandOwnerOnlyBypass{}).Apply(d)
		}},
		{"node pairing reconnect", "openclaw-node-pairing-reconnect-scope-confusion", "2026.5.26", "2026.5.27", func(d *parse.Document) []finding.Finding {
			return (openclawNodePairingReconnectScopeConfusion{}).Apply(d)
		}},
		{"shell option revalidation", "openclaw-shell-option-revalidation-bypass", "2026.5.11", "2026.5.12", func(d *parse.Document) []finding.Finding {
			return (openclawShellOptionRevalidationBypass{}).Apply(d)
		}},
		{"powershell encoded-command alias", "openclaw-powershell-encoded-command-alias-bypass", "2026.5.11", "2026.5.12", func(d *parse.Document) []finding.Finding {
			return (openclawPowerShellEncodedCommandAliasBypass{}).Apply(d)
		}},
		{"telegram callback allowfrom", "openclaw-telegram-callback-allowfrom-bypass", "2026.5.5", "2026.5.6", func(d *parse.Document) []finding.Finding {
			return (openclawTelegramCallbackAllowFromBypass{}).Apply(d)
		}},
		{"marketplace extension metadata", "openclaw-marketplace-extension-metadata-redirect", "2026.5.17", "2026.5.18", func(d *parse.Document) []finding.Finding {
			return (openclawMarketplaceExtensionMetadataRedirect{}).Apply(d)
		}},
		{"websocket operator scope", "openclaw-websocket-operator-scope-bypass", "2026.5.17", "2026.5.18", func(d *parse.Document) []finding.Finding {
			return (openclawWebsocketOperatorScopeBypass{}).Apply(d)
		}},
		{"shell wrapper argv mutation", "openclaw-shell-wrapper-argv-mutation", "2026.5.17", "2026.5.18", func(d *parse.Document) []finding.Finding {
			return (openclawShellWrapperArgvMutation{}).Apply(d)
		}},
		{"matrix allowfrom display name", "openclaw-matrix-allowfrom-displayname-bypass", "2026.5.6", "2026.5.7", func(d *parse.Document) []finding.Finding {
			return (openclawMatrixAllowFromDisplayNameBypass{}).Apply(d)
		}},
		{"slack allowfrom display name", "openclaw-slack-allowfrom-displayname-bypass", "2026.5.2", "2026.5.3", func(d *parse.Document) []finding.Finding {
			return (openclawSlackAllowFromDisplayNameBypass{}).Apply(d)
		}},
		{"browser control private network ssrf", "openclaw-browser-control-private-network-ssrf", "2026.5.17", "2026.5.18", func(d *parse.Document) []finding.Finding {
			return (openclawBrowserControlPrivateNetworkSSRF{}).Apply(d)
		}},
		{"memory-core artifact root traversal", "openclaw-memory-core-artifact-root-traversal", "2026.4.24", "2026.4.25", func(d *parse.Document) []finding.Finding {
			return (openclawMemoryCoreArtifactRootTraversal{}).Apply(d)
		}},
		{"hook-triggered owner loopback escalation", "openclaw-hook-triggered-owner-loopback-escalation", "2026.5.19", "2026.5.20", func(d *parse.Document) []finding.Finding {
			return (openclawHookTriggeredOwnerLoopbackEscalation{}).Apply(d)
		}},
		{"node event provenance forgery", "openclaw-node-event-provenance-forgery", "2026.5.17", "2026.5.18", func(d *parse.Document) []finding.Finding {
			return (openclawNodeEventProvenanceForgery{}).Apply(d)
		}},
		{"control ui pairing locality spoof", "openclaw-control-ui-pairing-locality-spoof", "2026.5.21", "2026.5.22", func(d *parse.Document) []finding.Finding {
			return (openclawControlUIPairingLocalitySpoof{}).Apply(d)
		}},
		{"skill install homebrew env override", "openclaw-skill-install-homebrew-env-override", "2026.5.26", "2026.5.27", func(d *parse.Document) []finding.Finding {
			return (openclawSkillInstallHomebrewEnvOverride{}).Apply(d)
		}},
		{"approval display truncation", "openclaw-approval-display-truncation", "2026.5.17", "2026.5.18", func(d *parse.Document) []finding.Finding {
			return (openclawApprovalDisplayTruncation{}).Apply(d)
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name+" vulnerable package", func(t *testing.T) {
			doc := parse.Parse("package.json", []byte(`{"name":"openclaw","version":"`+tc.vulnerable+`"}`))
			findings := tc.apply(doc)
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want 1", len(findings))
			}
			if findings[0].RuleID != tc.ruleID {
				t.Fatalf("rule id = %q, want %q", findings[0].RuleID, tc.ruleID)
			}
		})

		t.Run(tc.name+" vulnerable dependency", func(t *testing.T) {
			doc := parse.Parse("package.json", []byte(`{"dependencies":{"openclaw":"^`+tc.vulnerable+`"}}`))
			findings := tc.apply(doc)
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want 1", len(findings))
			}
		})

		t.Run(tc.name+" fixed", func(t *testing.T) {
			doc := parse.Parse("package.json", []byte(`{"name":"openclaw","version":"`+tc.fixed+`","dependencies":{"openclaw":"`+tc.fixed+`"}}`))
			findings := tc.apply(doc)
			if len(findings) != 0 {
				t.Fatalf("got %d findings, want 0", len(findings))
			}
		})
	}
}
