package admission

import (
	"context"
	"net/http"
	"strings"
	"unicode"

	esconfig "execution-substrate/es/config"
)

const (
	codeDestructiveShellCommandDenied   = "destructive_shell_command_denied"
	codeConfiguredStaticScriptDenied    = "configured_static_script_content_denied"
	codeAdmissionPolicyInputUnavailable = "admission_policy_input_unavailable"

	selectedDestructiveShellCommandPolicyID   AdmissionPolicyID = "execution-substrate.admission.selected-destructive-shell-command/v1"
	selectedDestructiveShellCommandMessage    string            = "destructive shell command denied by admission policy"
	configuredStaticScriptLiteralDenyPolicyID AdmissionPolicyID = "execution-substrate.admission.configured-static-script-literal-deny/v1"
	configuredStaticScriptLiteralDenyMessage  string            = "static script content denied by admission policy"
	admissionPolicyInputUnavailableMessage    string            = "admission policy input unavailable"
)

type AdmissionPolicyID string

type AdmissionPolicyReasonCode string

type AdmissionPolicyInputClass string

const (
	AdmissionPolicyInputInvocationArgv            AdmissionPolicyInputClass = "invocation_argv"
	AdmissionPolicyInputArtifactEvidenceMetadata  AdmissionPolicyInputClass = "artifact_evidence_metadata"
	AdmissionPolicyInputRuntimeProfileMetadata    AdmissionPolicyInputClass = "runtime_profile_metadata"
	AdmissionPolicyInputPayloadDigestAndByteCount AdmissionPolicyInputClass = "payload_digest_and_byte_count"
	AdmissionPolicyInputStaticScriptPayloadText   AdmissionPolicyInputClass = "static_script_payload_text"
)

type AdmissionPolicyEvaluator interface {
	RequiredInputClasses(AdmissionPolicyContext) []AdmissionPolicyInputClass
	Evaluate(context.Context, AdmissionPolicyContext) AdmissionPolicyDecision
}

type AdmissionPolicyContext struct {
	InvocationArgv                 []string
	ArtifactDigest                 string
	PayloadDigest                  string
	PayloadByteCount               int64
	ArtifactType                   string
	RuntimeProfileName             string
	TargetPlatform                 string
	NetworkAccess                  bool
	StaticScriptPayloadText        string `json:"-"`
	StaticScriptPayloadTextPresent bool
}

type AdmissionPolicyDecision struct {
	Allow                 bool                        `json:"allow"`
	PolicyID              AdmissionPolicyID           `json:"policy_id,omitempty"`
	ReasonCode            AdmissionPolicyReasonCode   `json:"reason_code,omitempty"`
	SafeMessage           string                      `json:"safe_message,omitempty"`
	InspectedInputClasses []AdmissionPolicyInputClass `json:"inspected_input_classes,omitempty"`
}

func AllowAdmissionPolicyDecision(inspected ...AdmissionPolicyInputClass) AdmissionPolicyDecision {
	return AdmissionPolicyDecision{
		Allow:                 true,
		InspectedInputClasses: normalizedAdmissionPolicyInputClasses(inspected),
	}
}

func DenyAdmissionPolicyDecision(policyID AdmissionPolicyID, reasonCode AdmissionPolicyReasonCode, safeMessage string, inspected ...AdmissionPolicyInputClass) AdmissionPolicyDecision {
	return AdmissionPolicyDecision{
		Allow:                 false,
		PolicyID:              policyID,
		ReasonCode:            reasonCode,
		SafeMessage:           strings.TrimSpace(safeMessage),
		InspectedInputClasses: normalizedAdmissionPolicyInputClasses(inspected),
	}
}

type admissionPolicySet struct {
	policies []AdmissionPolicyEvaluator
}

func defaultAdmissionPolicyEvaluator() AdmissionPolicyEvaluator {
	return admissionPolicyEvaluatorFromConfig(nil)
}

func admissionPolicyEvaluatorFromConfig(cfg *esconfig.AdmissionPolicyConfig) AdmissionPolicyEvaluator {
	policies := []AdmissionPolicyEvaluator{
		selectedDestructiveShellCommandPolicy{},
	}
	if policy := configuredStaticScriptLiteralDenyPolicyFromConfig(cfg); policy != nil {
		policies = append(policies, policy)
	}
	return admissionPolicySet{
		policies: policies,
	}
}

func (s admissionPolicySet) RequiredInputClasses(ctx AdmissionPolicyContext) []AdmissionPolicyInputClass {
	var required []AdmissionPolicyInputClass
	for _, policy := range s.policies {
		required = append(required, policy.RequiredInputClasses(ctx)...)
	}
	return normalizedAdmissionPolicyInputClasses(required)
}

func (s admissionPolicySet) Evaluate(ctx context.Context, policyCtx AdmissionPolicyContext) AdmissionPolicyDecision {
	var inspected []AdmissionPolicyInputClass
	for _, policy := range s.policies {
		decision := policy.Evaluate(ctx, policyCtx)
		inspected = append(inspected, decision.InspectedInputClasses...)
		if !decision.Allow {
			return decision
		}
	}
	return AllowAdmissionPolicyDecision(inspected...)
}

type selectedDestructiveShellCommandPolicy struct{}

func (selectedDestructiveShellCommandPolicy) RequiredInputClasses(ctx AdmissionPolicyContext) []AdmissionPolicyInputClass {
	if strings.TrimSpace(ctx.ArtifactType) != "static-script" {
		return nil
	}
	return []AdmissionPolicyInputClass{
		AdmissionPolicyInputArtifactEvidenceMetadata,
		AdmissionPolicyInputPayloadDigestAndByteCount,
		AdmissionPolicyInputStaticScriptPayloadText,
	}
}

func (selectedDestructiveShellCommandPolicy) Evaluate(_ context.Context, ctx AdmissionPolicyContext) AdmissionPolicyDecision {
	inspected := []AdmissionPolicyInputClass{
		AdmissionPolicyInputArtifactEvidenceMetadata,
	}
	if strings.TrimSpace(ctx.ArtifactType) != "static-script" {
		return AllowAdmissionPolicyDecision(inspected...)
	}
	inspected = append(inspected,
		AdmissionPolicyInputPayloadDigestAndByteCount,
		AdmissionPolicyInputStaticScriptPayloadText,
	)
	if hasSelectedDestructiveShellPattern(ctx.StaticScriptPayloadText) {
		return DenyAdmissionPolicyDecision(
			selectedDestructiveShellCommandPolicyID,
			AdmissionPolicyReasonCode(codeDestructiveShellCommandDenied),
			selectedDestructiveShellCommandMessage,
			inspected...,
		)
	}
	return AllowAdmissionPolicyDecision(inspected...)
}

type configuredStaticScriptLiteralDenyPolicy struct {
	entries []configuredStaticScriptLiteralDenyEntry
}

type configuredStaticScriptLiteralDenyEntry struct {
	id      string
	literal string
}

func configuredStaticScriptLiteralDenyPolicyFromConfig(cfg *esconfig.AdmissionPolicyConfig) AdmissionPolicyEvaluator {
	if cfg == nil || cfg.ConfiguredStaticScriptLiteralDeny == nil {
		return nil
	}
	policyCfg := cfg.ConfiguredStaticScriptLiteralDeny
	if policyCfg.Mode != esconfig.ConfiguredStaticScriptLiteralDenyModeEnforce || len(policyCfg.Entries) == 0 {
		return nil
	}
	entries := make([]configuredStaticScriptLiteralDenyEntry, 0, len(policyCfg.Entries))
	for _, entry := range policyCfg.Entries {
		entries = append(entries, configuredStaticScriptLiteralDenyEntry{
			id:      strings.TrimSpace(entry.ID),
			literal: entry.Literal,
		})
	}
	return configuredStaticScriptLiteralDenyPolicy{
		entries: entries,
	}
}

func (p configuredStaticScriptLiteralDenyPolicy) RequiredInputClasses(ctx AdmissionPolicyContext) []AdmissionPolicyInputClass {
	if len(p.entries) == 0 || strings.TrimSpace(ctx.ArtifactType) != "static-script" {
		return nil
	}
	return []AdmissionPolicyInputClass{
		AdmissionPolicyInputArtifactEvidenceMetadata,
		AdmissionPolicyInputPayloadDigestAndByteCount,
		AdmissionPolicyInputStaticScriptPayloadText,
	}
}

func (p configuredStaticScriptLiteralDenyPolicy) Evaluate(_ context.Context, ctx AdmissionPolicyContext) AdmissionPolicyDecision {
	inspected := []AdmissionPolicyInputClass{
		AdmissionPolicyInputArtifactEvidenceMetadata,
	}
	if len(p.entries) == 0 || strings.TrimSpace(ctx.ArtifactType) != "static-script" {
		return AllowAdmissionPolicyDecision(inspected...)
	}
	inspected = append(inspected,
		AdmissionPolicyInputPayloadDigestAndByteCount,
		AdmissionPolicyInputStaticScriptPayloadText,
	)
	for _, entry := range p.entries {
		if entry.literal != "" && strings.Contains(ctx.StaticScriptPayloadText, entry.literal) {
			return DenyAdmissionPolicyDecision(
				configuredStaticScriptLiteralDenyPolicyID,
				AdmissionPolicyReasonCode(codeConfiguredStaticScriptDenied),
				configuredStaticScriptLiteralDenyMessage,
				inspected...,
			)
		}
	}
	return AllowAdmissionPolicyDecision(inspected...)
}

func newAdmissionPolicyContext(req PrepareRequest, artifact preparedArtifact) AdmissionPolicyContext {
	return AdmissionPolicyContext{
		InvocationArgv:     append([]string(nil), req.Invocation.Argv...),
		ArtifactDigest:     strings.TrimSpace(req.Invocation.ArtifactDigest),
		PayloadDigest:      strings.TrimSpace(artifact.payloadDigest),
		ArtifactType:       strings.TrimSpace(artifact.manifest.ArtifactType),
		RuntimeProfileName: requestedRuntimeProfileName(req),
		TargetPlatform:     strings.TrimSpace(artifact.targetPlatform),
		NetworkAccess:      artifact.networkAccess,
	}
}

func requestedRuntimeProfileName(req PrepareRequest) string {
	requested := strings.TrimSpace(req.Invocation.Annotations[runtimeProfileAnnotationKey])
	if requested == "" {
		return runtimeProfileDefaultStaticScript
	}
	return requested
}

func normalizedAdmissionPolicyInputClasses(classes []AdmissionPolicyInputClass) []AdmissionPolicyInputClass {
	seen := map[AdmissionPolicyInputClass]struct{}{}
	normalized := make([]AdmissionPolicyInputClass, 0, len(classes))
	for _, class := range classes {
		if strings.TrimSpace(string(class)) == "" {
			continue
		}
		if _, ok := seen[class]; ok {
			continue
		}
		seen[class] = struct{}{}
		normalized = append(normalized, class)
	}
	return normalized
}

func policyDenialError(decision AdmissionPolicyDecision) *Error {
	code := strings.TrimSpace(string(decision.ReasonCode))
	message := strings.TrimSpace(decision.SafeMessage)
	if code == "" || message == "" {
		code = codeAdmissionPolicyInputUnavailable
		message = admissionPolicyInputUnavailableMessage
	}
	return &Error{
		Status:  http.StatusForbidden,
		Code:    code,
		Message: message,
	}
}

func admissionPolicyInputUnavailableError() *Error {
	return &Error{
		Status:  http.StatusForbidden,
		Code:    codeAdmissionPolicyInputUnavailable,
		Message: admissionPolicyInputUnavailableMessage,
	}
}

func hasSelectedDestructiveShellPattern(text string) bool {
	tokens := shellPolicyTokens(text)
	for _, pattern := range selectedDestructiveShellTokenSequences() {
		if containsShellPolicyTokenSequence(tokens, pattern) {
			return true
		}
	}
	return false
}

func selectedDestructiveShellTokenSequences() [][]string {
	removeToken := strings.Join([]string{"r", "m"}, "")
	return [][]string{
		{removeToken, "-rf", "/"},
		{removeToken, "-fr", "/"},
	}
}

func shellPolicyTokens(text string) []string {
	fields := strings.FieldsFunc(text, func(r rune) bool {
		return unicode.IsSpace(r) || strings.ContainsRune(";&|(){}[]<>", r)
	})
	tokens := make([]string, 0, len(fields))
	for _, field := range fields {
		token := strings.Trim(strings.TrimSpace(field), `"'`)
		if token == "" {
			continue
		}
		tokens = append(tokens, token)
	}
	return tokens
}

func containsShellPolicyTokenSequence(tokens []string, pattern []string) bool {
	if len(pattern) == 0 || len(tokens) < len(pattern) {
		return false
	}
	for i := 0; i <= len(tokens)-len(pattern); i++ {
		matched := true
		for j := range pattern {
			if tokens[i+j] != pattern[j] {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}
