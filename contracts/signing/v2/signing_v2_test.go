package signingv2

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

func TestCanonicalProvenancePayloadIsFrozen(t *testing.T) {
	t.Parallel()

	payload := ProvenancePayload{
		Kind: KindProvenance,
		Subject: ProvenanceSubject{
			ArtifactDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		},
		Claims: ProvenanceClaims{
			BuilderService: "artifact-governance",
			Invoker: ProvenanceInvoker{
				Service:   "deployment",
				Principal: "spiffe://monolith.internal/service/deployment",
			},
			PolicyDecisions: []PolicyDecision{
				{Rule: "deny", Result: "skipped"},
				{Rule: "allow", Result: "applied"},
			},
			BuildLogDigest: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		},
	}

	got, err := CanonicalProvenancePayload(payload)
	if err != nil {
		t.Fatalf("canonicalize provenance: %v", err)
	}
	want := `{"claims":{"build_log_digest":"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","builder_service":"artifact-governance","invoker":{"principal":"spiffe://monolith.internal/service/deployment","service":"deployment"},"policy_decisions":[{"result":"applied","rule":"allow"},{"result":"skipped","rule":"deny"}]},"kind":"provenance","subject":{"artifact_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111"}}`
	if string(got) != want {
		t.Fatalf("unexpected canonical provenance:\nwant: %s\ngot:  %s", want, string(got))
	}
}

func TestCanonicalDerivationAttestationPayloadIsFrozen(t *testing.T) {
	t.Parallel()

	payload := sampleDerivationPayload()
	got, err := CanonicalDerivationAttestationPayload(payload)
	if err != nil {
		t.Fatalf("canonicalize derivation attestation: %v", err)
	}
	want := `{"claims":{"constraints":{"allowed_toolchains":["gcc","zig"],"arch":"amd64","determinism_expectation":"deterministic","forbidden_paths":["/proc","/sys"],"forbidden_toolchains":["curl","wget"],"network_access":false,"os":"linux","writable_paths":["/tmp","/workspace"]},"policy":{"expected_artifact_type":"static-service","version":"2026-03-31"}},"kind":"derivation_attestation","subject":{"artifact_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","derivation_spec_digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","output_id":"runtime"}}`
	if string(got) != want {
		t.Fatalf("unexpected canonical derivation attestation:\nwant: %s\ngot:  %s", want, string(got))
	}
}

func TestCanonicalWorkloadIdentityBindingPayloadIsFrozen(t *testing.T) {
	t.Parallel()

	payload := sampleBindingPayload()
	got, err := CanonicalWorkloadIdentityBindingPayload(payload)
	if err != nil {
		t.Fatalf("canonicalize workload identity binding: %v", err)
	}
	want := `{"claims":{"descriptor":{"description":"Execution workload","module_path":"services.execution.ExecutionServer","service_name":"execution","target_platform":"docker","workload_identity_id":"spiffe://monolith.internal/service/execution","workload_type":"service"},"policy":{"version":"2026-03-31"}},"kind":"workload_identity_binding","subject":{"artifact_class":"service","artifact_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","derivation_spec_digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","output_id":"runtime"}}`
	if string(got) != want {
		t.Fatalf("unexpected canonical workload identity binding:\nwant: %s\ngot:  %s", want, string(got))
	}
}

func TestPayloadDigestIsDeterministic(t *testing.T) {
	t.Parallel()

	canonical, err := CanonicalDerivationAttestationPayload(sampleDerivationPayload())
	if err != nil {
		t.Fatalf("canonicalize derivation attestation: %v", err)
	}
	want := "sha256:e4cda17379f2679d0844a7688984063ef7cd18b5b46d338f9384d42b33046585"
	if got := PayloadDigest(canonical); got != want {
		t.Fatalf("unexpected payload digest: want %s got %s", want, got)
	}
}

func TestVerifyEnvelopeAcceptsValidSignature(t *testing.T) {
	t.Parallel()

	privateKey, publicKey := deterministicKeypair()
	canonical, err := CanonicalWorkloadIdentityBindingPayload(sampleBindingPayload())
	if err != nil {
		t.Fatalf("canonicalize binding: %v", err)
	}
	envelope := NewEnvelope(canonical, "ags-signing-key-v2", "ed25519", base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical)))

	if err := VerifyEnvelope(canonical, envelope, "ags-signing-key-v2", "ed25519", publicKey); err != nil {
		t.Fatalf("verify envelope: %v", err)
	}
}

func TestVerifyEnvelopeRejectsModifiedPayload(t *testing.T) {
	t.Parallel()

	privateKey, publicKey := deterministicKeypair()
	original, err := CanonicalProvenancePayload(sampleProvenancePayload())
	if err != nil {
		t.Fatalf("canonicalize original provenance: %v", err)
	}
	modifiedPayload := sampleProvenancePayload()
	modifiedPayload.Claims.BuildLogDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	modified, err := CanonicalProvenancePayload(modifiedPayload)
	if err != nil {
		t.Fatalf("canonicalize modified provenance: %v", err)
	}
	envelope := NewEnvelope(original, "ags-signing-key-v2", "ed25519", base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, original)))

	if err := VerifyEnvelope(modified, envelope, "ags-signing-key-v2", "ed25519", publicKey); err == nil || err.Error() != "payload digest mismatch" {
		t.Fatalf("expected payload digest mismatch, got %v", err)
	}
}

func TestVerifyEnvelopeRejectsModifiedSignature(t *testing.T) {
	t.Parallel()

	privateKey, publicKey := deterministicKeypair()
	canonical, err := CanonicalWorkloadIdentityBindingPayload(sampleBindingPayload())
	if err != nil {
		t.Fatalf("canonicalize binding: %v", err)
	}
	envelope := NewEnvelope(canonical, "ags-signing-key-v2", "ed25519", base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical)))
	envelope.SignatureValue = base64.StdEncoding.EncodeToString([]byte("invalid-signature"))

	if err := VerifyEnvelope(canonical, envelope, "ags-signing-key-v2", "ed25519", publicKey); err == nil || err.Error() != "signature verification failed" {
		t.Fatalf("expected signature verification failed, got %v", err)
	}
}

func TestVerifyEnvelopeRejectsMismatchedDigest(t *testing.T) {
	t.Parallel()

	privateKey, publicKey := deterministicKeypair()
	canonical, err := CanonicalDerivationAttestationPayload(sampleDerivationPayload())
	if err != nil {
		t.Fatalf("canonicalize derivation attestation: %v", err)
	}
	envelope := NewEnvelope(canonical, "ags-signing-key-v2", "ed25519", base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical)))
	envelope.PayloadDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

	if err := VerifyEnvelope(canonical, envelope, "ags-signing-key-v2", "ed25519", publicKey); err == nil || err.Error() != "payload digest mismatch" {
		t.Fatalf("expected payload digest mismatch, got %v", err)
	}
}

func TestCanonicalizationOmitsEmptyOptionalFields(t *testing.T) {
	t.Parallel()

	payload := sampleBindingPayload()
	payload.Claims.Descriptor.Description = ""
	payload.Claims.Descriptor.ServiceName = ""
	payload.Claims.Descriptor.TargetPlatform = ""
	payload.Claims.Descriptor.WorkloadIdentityID = ""
	got, err := CanonicalWorkloadIdentityBindingPayload(payload)
	if err != nil {
		t.Fatalf("canonicalize binding: %v", err)
	}
	want := `{"claims":{"descriptor":{"module_path":"services.execution.ExecutionServer","workload_type":"service"},"policy":{"version":"2026-03-31"}},"kind":"workload_identity_binding","subject":{"artifact_class":"service","artifact_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","derivation_spec_digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","output_id":"runtime"}}`
	if string(got) != want {
		t.Fatalf("unexpected optional-field canonicalization:\nwant: %s\ngot:  %s", want, string(got))
	}
}

func TestCanonicalizationNormalizesSetOrdering(t *testing.T) {
	t.Parallel()

	left := sampleDerivationPayload()
	right := sampleDerivationPayload()
	left.Claims.Constraints.AllowedToolchains = []string{"zig", "gcc"}
	right.Claims.Constraints.AllowedToolchains = []string{"gcc", "zig"}

	leftBytes, err := CanonicalDerivationAttestationPayload(left)
	if err != nil {
		t.Fatalf("canonicalize left: %v", err)
	}
	rightBytes, err := CanonicalDerivationAttestationPayload(right)
	if err != nil {
		t.Fatalf("canonicalize right: %v", err)
	}
	if string(leftBytes) != string(rightBytes) {
		t.Fatalf("expected equal canonical payloads, got\nleft:  %s\nright: %s", string(leftBytes), string(rightBytes))
	}
}

func TestCanonicalJSONPreservesSemanticArrayOrder(t *testing.T) {
	t.Parallel()

	left, err := canonicalJSON(map[string]any{"steps": []any{"first", "second"}})
	if err != nil {
		t.Fatalf("canonicalize left array: %v", err)
	}
	right, err := canonicalJSON(map[string]any{"steps": []any{"second", "first"}})
	if err != nil {
		t.Fatalf("canonicalize right array: %v", err)
	}
	if string(left) == string(right) {
		t.Fatalf("expected array order to be preserved, got identical outputs %s", string(left))
	}
}

func TestCanonicalJSONSortsNestedObjectKeys(t *testing.T) {
	t.Parallel()

	got, err := canonicalJSON(map[string]any{
		"outer": map[string]any{
			"z": "last",
			"a": "first",
		},
	})
	if err != nil {
		t.Fatalf("canonicalize nested map: %v", err)
	}
	want := `{"outer":{"a":"first","z":"last"}}`
	if string(got) != want {
		t.Fatalf("unexpected nested key ordering:\nwant: %s\ngot:  %s", want, string(got))
	}
}

func TestCanonicalizationIsStableForUnicodeAndWhitespace(t *testing.T) {
	t.Parallel()

	payload := sampleBindingPayload()
	payload.Claims.Descriptor.Description = "Line 1\nLine 2\tSnowman: \u2603"
	first, err := CanonicalWorkloadIdentityBindingPayload(payload)
	if err != nil {
		t.Fatalf("canonicalize first payload: %v", err)
	}
	second, err := CanonicalWorkloadIdentityBindingPayload(payload)
	if err != nil {
		t.Fatalf("canonicalize second payload: %v", err)
	}
	if string(first) != string(second) {
		t.Fatalf("expected deterministic Unicode canonicalization:\nfirst:  %s\nsecond: %s", string(first), string(second))
	}
}

func sampleProvenancePayload() ProvenancePayload {
	return ProvenancePayload{
		Kind: KindProvenance,
		Subject: ProvenanceSubject{
			ArtifactDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		},
		Claims: ProvenanceClaims{
			BuilderService: "artifact-governance",
			Invoker: ProvenanceInvoker{
				Service:   "deployment",
				Principal: "spiffe://monolith.internal/service/deployment",
			},
			PolicyDecisions: []PolicyDecision{
				{Rule: "allow", Result: "applied"},
				{Rule: "deny", Result: "skipped"},
			},
			BuildLogDigest: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		},
	}
}

func sampleDerivationPayload() DerivationAttestationPayload {
	return DerivationAttestationPayload{
		Kind: KindDerivationAttestation,
		Subject: DerivationSubject{
			ArtifactDigest:       "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			DerivationSpecDigest: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
			OutputID:             "runtime",
		},
		Claims: DerivationAttestationClaims{
			Constraints: DerivationConstraints{
				AllowedToolchains:      []string{"zig", "gcc"},
				ForbiddenToolchains:    []string{"wget", "curl"},
				OS:                     "linux",
				Arch:                   "amd64",
				NetworkAccess:          false,
				WritablePaths:          []string{"/workspace", "/tmp"},
				ForbiddenPaths:         []string{"/sys", "/proc"},
				DeterminismExpectation: "deterministic",
			},
			Policy: DerivationPolicy{
				Version:              "2026-03-31",
				ExpectedArtifactType: "static-service",
			},
		},
	}
}

func sampleBindingPayload() WorkloadIdentityBindingPayload {
	return WorkloadIdentityBindingPayload{
		Kind: KindWorkloadIdentityBinding,
		Subject: WorkloadIdentitySubject{
			ArtifactClass:        "service",
			ArtifactDigest:       "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			DerivationSpecDigest: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
			OutputID:             "runtime",
		},
		Claims: WorkloadIdentityBindingClaims{
			Descriptor: WorkloadDescriptor{
				WorkloadType:       "service",
				ModulePath:         "services.execution.ExecutionServer",
				ServiceName:        "execution",
				TargetPlatform:     "docker",
				Description:        "Execution workload",
				WorkloadIdentityID: "spiffe://monolith.internal/service/execution",
			},
			Policy: WorkloadPolicy{
				Version: "2026-03-31",
			},
		},
	}
}

func deterministicKeypair() (ed25519.PrivateKey, ed25519.PublicKey) {
	seed := []byte("01234567890123456789012345678901")
	privateKey := ed25519.NewKeyFromSeed(seed)
	return privateKey, privateKey.Public().(ed25519.PublicKey)
}
