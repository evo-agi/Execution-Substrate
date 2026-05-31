package admission

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	esconfig "execution-substrate/es/config"
)

func TestAdmissionPolicyDecisionShapeRecordsSafeMetadataOnly(t *testing.T) {
	allow := AllowAdmissionPolicyDecision(
		AdmissionPolicyInputInvocationArgv,
		AdmissionPolicyInputInvocationArgv,
		AdmissionPolicyInputRuntimeProfileMetadata,
	)
	if !allow.Allow {
		t.Fatal("expected allow decision")
	}
	if len(allow.InspectedInputClasses) != 2 {
		t.Fatalf("expected deduplicated inspected input classes, got %d", len(allow.InspectedInputClasses))
	}

	fixture := selectedPatternFixtureText()
	deny := DenyAdmissionPolicyDecision(
		selectedDestructiveShellCommandPolicyID,
		AdmissionPolicyReasonCode(codeDestructiveShellCommandDenied),
		selectedDestructiveShellCommandMessage,
		AdmissionPolicyInputStaticScriptPayloadText,
		AdmissionPolicyInputPayloadDigestAndByteCount,
	)
	if deny.Allow {
		t.Fatal("expected deny decision")
	}
	if deny.PolicyID != selectedDestructiveShellCommandPolicyID {
		t.Fatalf("unexpected policy id %q", deny.PolicyID)
	}
	if deny.ReasonCode != AdmissionPolicyReasonCode(codeDestructiveShellCommandDenied) {
		t.Fatalf("unexpected reason code %q", deny.ReasonCode)
	}
	if deny.SafeMessage != selectedDestructiveShellCommandMessage {
		t.Fatalf("unexpected safe message %q", deny.SafeMessage)
	}
	decisionPayload := mustMarshalWorkstreamCTestJSON(t, deny)
	assertOmitsPolicyFixture(t, decisionPayload, fixture)
}

func TestSelectedStaticScriptPolicyAllowsBenignAndDeniesSelectedPattern(t *testing.T) {
	policy := selectedDestructiveShellCommandPolicy{}
	benign := newStaticScriptPolicyContext(benignPolicyFixtureText())
	benignDecision := policy.Evaluate(context.Background(), benign)
	if !benignDecision.Allow {
		t.Fatalf("expected benign static-script text to be allowed with reason %q", benignDecision.ReasonCode)
	}
	assertAdmissionPolicyInputClasses(t, benignDecision.InspectedInputClasses,
		AdmissionPolicyInputArtifactEvidenceMetadata,
		AdmissionPolicyInputPayloadDigestAndByteCount,
		AdmissionPolicyInputStaticScriptPayloadText,
	)

	selectedFixture := selectedPatternFixtureText()
	denied := policy.Evaluate(context.Background(), newStaticScriptPolicyContext(selectedFixture))
	if denied.Allow {
		t.Fatal("expected selected-pattern fixture to be denied")
	}
	if denied.PolicyID != selectedDestructiveShellCommandPolicyID ||
		denied.ReasonCode != AdmissionPolicyReasonCode(codeDestructiveShellCommandDenied) ||
		denied.SafeMessage != selectedDestructiveShellCommandMessage {
		t.Fatalf("unexpected safe denial metadata id=%q code=%q message=%q", denied.PolicyID, denied.ReasonCode, denied.SafeMessage)
	}
	assertOmitsPolicyFixture(t, denied.SafeMessage, selectedFixture)
	decisionPayload := mustMarshalWorkstreamCTestJSON(t, denied)
	assertOmitsPolicyFixture(t, decisionPayload, selectedFixture)
}

func TestConfiguredStaticScriptLiteralDenyPolicyAllowsBenignPayload(t *testing.T) {
	policy := configuredStaticScriptLiteralDenyPolicyForTest(configuredPolicyFixtureMarker())

	decision := policy.Evaluate(context.Background(), newStaticScriptPolicyContext(benignPolicyFixtureText()))
	if !decision.Allow {
		t.Fatalf("expected configured literal deny policy to allow benign payload, got %s", decision.ReasonCode)
	}
	assertAdmissionPolicyInputClasses(t, decision.InspectedInputClasses,
		AdmissionPolicyInputArtifactEvidenceMetadata,
		AdmissionPolicyInputPayloadDigestAndByteCount,
		AdmissionPolicyInputStaticScriptPayloadText,
	)
}

func TestConfiguredStaticScriptLiteralDenyPolicyDeniesConfiguredMarkerWithSafeMetadata(t *testing.T) {
	marker := configuredPolicyFixtureMarker()
	policy := configuredStaticScriptLiteralDenyPolicyForTest(marker)

	denied := policy.Evaluate(context.Background(), newStaticScriptPolicyContext("echo before\n"+marker+"\necho after\n"))
	if denied.Allow {
		t.Fatal("expected configured literal marker to be denied")
	}
	if denied.PolicyID != configuredStaticScriptLiteralDenyPolicyID ||
		denied.ReasonCode != AdmissionPolicyReasonCode(codeConfiguredStaticScriptDenied) ||
		denied.SafeMessage != configuredStaticScriptLiteralDenyMessage {
		t.Fatalf("unexpected configured literal denial metadata: %s %s %q", denied.PolicyID, denied.ReasonCode, denied.SafeMessage)
	}
	assertOmitsPolicyFixture(t, denied.SafeMessage, marker)
	decisionPayload := mustMarshalWorkstreamCTestJSON(t, denied)
	assertOmitsPolicyFixture(t, decisionPayload, marker)
}

func TestConfiguredStaticScriptLiteralDenyPolicyTreatsRegexLikeEntryAsLiteral(t *testing.T) {
	regexLookingLiteral := "^ES_DEMO_LITERAL_MARKER.*$"
	policy := configuredStaticScriptLiteralDenyPolicyForTest(regexLookingLiteral)

	regexMatchOnly := policy.Evaluate(context.Background(), newStaticScriptPolicyContext("echo ES_DEMO_LITERAL_MARKER_SUFFIX"))
	if !regexMatchOnly.Allow {
		t.Fatalf("regex-looking configured entry must not act as regex, got %s", regexMatchOnly.ReasonCode)
	}

	exactLiteral := policy.Evaluate(context.Background(), newStaticScriptPolicyContext("echo "+regexLookingLiteral))
	if exactLiteral.Allow {
		t.Fatal("expected exact regex-looking literal text to be denied")
	}
	assertOmitsPolicyFixture(t, exactLiteral.SafeMessage, regexLookingLiteral)
}

func TestConfiguredStaticScriptLiteralDenyPolicyIsBuiltFromESAdminConfigOnly(t *testing.T) {
	evaluator := admissionPolicyEvaluatorFromConfig(&esconfig.AdmissionPolicyConfig{
		ConfiguredStaticScriptLiteralDeny: &esconfig.ConfiguredStaticScriptLiteralDenyPolicyConfig{
			Mode: esconfig.ConfiguredStaticScriptLiteralDenyModeEnforce,
			Entries: []esconfig.ConfiguredStaticScriptLiteralDenyEntryConfig{
				{
					ID:         "demo-marker",
					InputClass: esconfig.ConfiguredStaticScriptLiteralDenyInputClassStaticScriptPayloadText,
					Literal:    configuredPolicyFixtureMarker(),
				},
			},
		},
	})

	denied := evaluator.Evaluate(context.Background(), newStaticScriptPolicyContext(configuredPolicyFixtureMarker()))
	if denied.Allow || denied.PolicyID != configuredStaticScriptLiteralDenyPolicyID {
		t.Fatalf("expected ES-admin configured built-in policy denial, got allow=%v policy=%s", denied.Allow, denied.PolicyID)
	}
}

func TestConfiguredStaticScriptLiteralDenyPolicyDisabledModeDoesNotDenyMatchingLiteral(t *testing.T) {
	marker := configuredPolicyFixtureMarker()
	evaluator := admissionPolicyEvaluatorFromConfig(&esconfig.AdmissionPolicyConfig{
		ConfiguredStaticScriptLiteralDeny: &esconfig.ConfiguredStaticScriptLiteralDenyPolicyConfig{
			Mode: esconfig.ConfiguredStaticScriptLiteralDenyModeDisabled,
			Entries: []esconfig.ConfiguredStaticScriptLiteralDenyEntryConfig{
				{
					ID:         "configured-marker",
					InputClass: esconfig.ConfiguredStaticScriptLiteralDenyInputClassStaticScriptPayloadText,
					Literal:    marker,
				},
			},
		},
	})

	decision := evaluator.Evaluate(context.Background(), newStaticScriptPolicyContext(marker))
	if !decision.Allow {
		t.Fatalf("expected disabled configured literal policy not to deny, got %s", decision.ReasonCode)
	}
}

func TestAdmissionPolicyPayloadInputExtractsBoundedStaticScriptText(t *testing.T) {
	payload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})

	text, err := staticScriptPayloadTextForAdmissionPolicy(payload)
	if err != nil {
		t.Fatalf("expected bounded static-script text extraction to succeed, got %+v", err)
	}
	if text != benignPolicyFixtureText() {
		t.Fatalf("unexpected extracted static-script text length %d", len(text))
	}
}

func TestAdmissionPolicyPayloadInputFailsSafelyWhenOversizedOrMalformed(t *testing.T) {
	oversized := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: bytes.Repeat([]byte("a"), maxAdmissionPolicyStaticScriptTextBytes+1),
	})
	if _, err := staticScriptPayloadTextForAdmissionPolicy(oversized); err == nil || err.Code != codeAdmissionPolicyInputUnavailable {
		t.Fatalf("expected oversized static-script input to fail safely, got %+v", err)
	}

	if _, err := staticScriptPayloadTextForAdmissionPolicy([]byte("not-a-supported-static-script-archive")); err == nil || err.Code != codeAdmissionPolicyInputUnavailable {
		t.Fatalf("expected malformed static-script input to fail safely, got %+v", err)
	}

	unsafe := buildAdmissionPolicyStaticScriptArchiveWithHeaderNames(t, map[string][]byte{
		"../entrypoint": []byte(benignPolicyFixtureText()),
	})
	if _, err := staticScriptPayloadTextForAdmissionPolicy(unsafe); err == nil || err.Code != codeAdmissionPolicyInputUnavailable {
		t.Fatalf("expected unsafe static-script archive path to fail safely, got %+v", err)
	}
}

func TestAdmissionPolicyPayloadInputDoesNotDecodeNestedArchives(t *testing.T) {
	nested := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(selectedPatternFixtureText()),
	})
	payload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
		"workspace/archive.tgz":    nested,
	})

	text, err := staticScriptPayloadTextForAdmissionPolicy(payload)
	if err != nil {
		t.Fatalf("expected top-level static-script text extraction, got %+v", err)
	}
	decision := selectedDestructiveShellCommandPolicy{}.Evaluate(context.Background(), newStaticScriptPolicyContext(text))
	if !decision.Allow {
		t.Fatalf("expected nested archive content to stay outside policy inspection, got safe code %q", decision.ReasonCode)
	}
}

func TestAdmissionPolicyFetchesPayloadThroughExplicitPayloadDigest(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, _, _ := newWorkstreamCTestService(t, fixture)
	payload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})

	arsCalls := map[string]int{}
	service.arsClient = newArtifactRegistryTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arsCalls[r.URL.Path]++
		switch r.URL.Path {
		case "/v1/blobs/" + fixture.discovery.Payload.Digest + ":bytes":
			_, _ = w.Write(payload)
		default:
			t.Fatalf("unexpected policy payload ARS path %q", r.URL.Path)
		}
	}))

	fetched, err := service.fetchAdmissionPolicyPayloadBytes(context.Background(), fixture.discovery.Payload.Digest)
	if err != nil {
		t.Fatalf("expected policy payload fetch to succeed, got %+v", err)
	}
	if len(fetched) != len(payload) {
		t.Fatalf("unexpected fetched payload length %d", len(fetched))
	}
	assertExactCallCount(t, arsCalls, "/v1/blobs/"+fixture.discovery.Payload.Digest+":bytes", 1)
	if len(arsCalls) != 1 {
		t.Fatalf("expected only explicit payload digest read, got %d ARS calls", len(arsCalls))
	}
}

func TestAdmissionPolicyAPIDenialErrorIsRedacted(t *testing.T) {
	fixture := selectedPatternFixtureText()
	err := policyDenialError(DenyAdmissionPolicyDecision(
		selectedDestructiveShellCommandPolicyID,
		AdmissionPolicyReasonCode(codeDestructiveShellCommandDenied),
		selectedDestructiveShellCommandMessage,
		AdmissionPolicyInputStaticScriptPayloadText,
	))
	body, marshalErr := json.Marshal(ErrorResponse{
		Success: false,
		Error:   err.Message,
		Code:    err.Code,
	})
	if marshalErr != nil {
		t.Fatalf("marshal redacted API error: %v", marshalErr)
	}
	if err.Status != http.StatusForbidden || err.Code != codeDestructiveShellCommandDenied || err.Message != selectedDestructiveShellCommandMessage {
		t.Fatalf("unexpected safe policy error status=%d code=%q message=%q", err.Status, err.Code, err.Message)
	}
	assertOmitsPolicyFixture(t, string(body), fixture)
	assertTextOmitsAll(t, string(body),
		`"policy_id"`,
		`"matched"`,
		`"prompt"`,
		`"workspace"`,
		`"model_output"`,
		`"logs"`,
		`"support_bundle"`,
		`"retained_bundle"`,
	)
}

func assertOmitsPolicyFixture(t *testing.T, text string, fixture string) {
	t.Helper()
	if strings.Contains(text, fixture) {
		t.Fatal("expected text to omit raw policy fixture content")
	}
}

func newStaticScriptPolicyContext(text string) AdmissionPolicyContext {
	return AdmissionPolicyContext{
		ArtifactDigest:                 labeledDigest("aa"),
		PayloadDigest:                  labeledDigest("bb"),
		PayloadByteCount:               int64(len(text)),
		ArtifactType:                   "static-script",
		RuntimeProfileName:             runtimeProfileDefaultStaticScript,
		StaticScriptPayloadText:        text,
		StaticScriptPayloadTextPresent: true,
	}
}

func benignPolicyFixtureText() string {
	return "#!/bin/sh\nprintf '%s\\n' policy-fixture-ok\n"
}

func configuredPolicyFixtureMarker() string {
	return "ES_DEMO_LITERAL_MARKER"
}

func configuredStaticScriptLiteralDenyPolicyForTest(literal string) configuredStaticScriptLiteralDenyPolicy {
	return configuredStaticScriptLiteralDenyPolicy{
		entries: []configuredStaticScriptLiteralDenyEntry{
			{
				id:      "demo-marker",
				literal: literal,
			},
		},
	}
}

func configureConfiguredStaticScriptLiteralDenyService(service *Service, literal string) {
	configureConfiguredStaticScriptLiteralDenyServiceMode(service, esconfig.ConfiguredStaticScriptLiteralDenyModeEnforce, literal)
}

func configureConfiguredStaticScriptLiteralDenyServiceMode(service *Service, mode esconfig.ConfiguredStaticScriptLiteralDenyPolicyMode, literal string) {
	cfg := &esconfig.AdmissionPolicyConfig{
		ConfiguredStaticScriptLiteralDeny: &esconfig.ConfiguredStaticScriptLiteralDenyPolicyConfig{
			Mode: mode,
			Entries: []esconfig.ConfiguredStaticScriptLiteralDenyEntryConfig{
				{
					ID:         "demo-marker",
					InputClass: esconfig.ConfiguredStaticScriptLiteralDenyInputClassStaticScriptPayloadText,
					Literal:    literal,
				},
			},
		},
	}
	service.cfg.AdmissionPolicy = cfg
	service.admissionPolicyEvaluator = admissionPolicyEvaluatorFromConfig(cfg)
}

func selectedPatternFixtureText() string {
	return strings.Join([]string{
		"#!/bin/sh",
		strings.Join([]string{"r", "m"}, ""),
		"-rf",
		"/",
		"# inert policy fixture; never executed",
	}, "\n")
}

func buildAdmissionPolicyStaticScriptArchive(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	return buildAdmissionPolicyStaticScriptArchiveWithHeaderNames(t, files)
}

func buildAdmissionPolicyStaticScriptArchiveWithHeaderNames(t *testing.T, files map[string][]byte) []byte {
	t.Helper()

	var archiveBuffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&archiveBuffer)
	tarWriter := tar.NewWriter(gzipWriter)
	for name, body := range files {
		header := &tar.Header{
			Name: name,
			Mode: 0o755,
			Size: int64(len(body)),
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatalf("write policy fixture tar header: %v", err)
		}
		if _, err := tarWriter.Write(body); err != nil {
			t.Fatalf("write policy fixture tar body: %v", err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("close policy fixture tar writer: %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("close policy fixture gzip writer: %v", err)
	}
	return archiveBuffer.Bytes()
}

func assertAdmissionPolicyInputClasses(t *testing.T, got []AdmissionPolicyInputClass, want ...AdmissionPolicyInputClass) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("expected %d inspected input classes, got %d", len(want), len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected inspected input class at index %d", i)
		}
	}
}
