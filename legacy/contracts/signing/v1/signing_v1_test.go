package signingv1

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

func TestCanonicalProvenanceBytesAreFrozen(t *testing.T) {
	t.Parallel()

	claims := ProvenanceClaims{
		ArtifactDigest:   "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		BuilderService:   "artifact-governance",
		InvokerService:   "deployment",
		InvokerPrincipal: "spiffe://monolith.internal/service/deployment",
		PolicyDecisions: []PolicyDecisionEntry{
			{Rule: "deny", Result: "skipped"},
			{Rule: "allow", Result: "applied"},
		},
		BuildLogDigest: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
	}

	got := string(CanonicalProvenanceBytes(claims))
	want := `{"artifact_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","builder_service":"artifact-governance","invoker_service":"deployment","invoker_principal":"spiffe://monolith.internal/service/deployment","policy_decisions_hash":"sha256:23b4401c63d084c3e5732fe74f5fca697c25921deacfb70b452a79bc80cc9230","build_log_digest":"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}`
	if got != want {
		t.Fatalf("unexpected canonical provenance bytes:\nwant: %s\ngot:  %s", want, got)
	}
}

func TestCanonicalDerivationAttestationBytesAreFrozen(t *testing.T) {
	t.Parallel()

	claims := DerivationAttestationClaims{
		Subject: DerivationSubjectClaims{
			ArtifactDigest:       "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			DerivationSpecDigest: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
			OutputID:             "runtime",
		},
		Constraints: DerivationConstraintsClaims{
			AllowedToolchains:      []string{},
			ForbiddenToolchains:    []string{},
			OS:                     "linux",
			Arch:                   "amd64",
			NetworkAccess:          false,
			WritablePaths:          []string{},
			ForbiddenPaths:         []string{},
			DeterminismExpectation: "deterministic",
		},
		Policy: DerivationPolicyClaims{
			Version:              "2026-03-31",
			ExpectedArtifactType: "static-service",
		},
	}

	got := string(CanonicalDerivationAttestationBytes(claims))
	want := `{"artifact_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","derivation_spec_digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","output_id":"runtime","constraints":{"allowed_toolchains":[],"forbidden_toolchains":[],"os":"linux","arch":"amd64","network_access":false,"writable_paths":[],"forbidden_paths":[],"determinism_expectation":"deterministic"},"policy_version":"2026-03-31","expected_artifact_type":"static-service"}`
	if got != want {
		t.Fatalf("unexpected canonical derivation bytes:\nwant: %s\ngot:  %s", want, got)
	}
}

func TestCanonicalWorkloadIdentityBindingBytesAreFrozen(t *testing.T) {
	t.Parallel()

	claims := WorkloadIdentityBindingClaims{
		Subject: WorkloadIdentitySubjectClaims{
			ArtifactClass:        "service",
			ArtifactDigest:       "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			DerivationSpecDigest: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
			OutputID:             "runtime",
			PolicyVersion:        "2026-03-31",
		},
		Descriptor: WorkloadDescriptorClaims{
			WorkloadType:       "service",
			ModulePath:         "services.execution.ExecutionServer",
			ServiceName:        "execution",
			TargetPlatform:     "docker",
			Description:        "Execution workload",
			WorkloadIdentityID: "spiffe://monolith.internal/service/execution",
		},
	}

	got := string(CanonicalWorkloadIdentityBindingBytes(claims))
	want := `{"artifact_class":"service","artifact_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","derivation_spec_digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","description":"Execution workload","module_path":"services.execution.ExecutionServer","output_id":"runtime","policy_version":"2026-03-31","service_name":"execution","target_platform":"docker","workload_identity_id":"spiffe://monolith.internal/service/execution","workload_type":"service"}`
	if got != want {
		t.Fatalf("unexpected canonical workload identity bytes:\nwant: %s\ngot:  %s", want, got)
	}
}

func TestCanonicalTrustModelBytesAreFrozen(t *testing.T) {
	t.Parallel()

	claims := TrustModelClaims{
		AllowedSigners:   []string{"ags-signing-key-v2", "ags-signing-key-v1"},
		RevokedSigners:   []string{"ags-signing-key-old", "ags-signing-key-compromised"},
		RevokedArtifacts: []string{"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		UpdateRevision:   3,
		Version:          "v1",
	}

	gotBytes, err := CanonicalTrustModelBytes(claims)
	if err != nil {
		t.Fatalf("canonicalize trust model: %v", err)
	}
	got := string(gotBytes)
	want := `{"artifact_policy":{"revoked_artifacts":["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]},"signer_policy":{"allowed_signers":["ags-signing-key-v1","ags-signing-key-v2"],"revoked_signers":["ags-signing-key-compromised","ags-signing-key-old"]},"update_revision":3,"version":"v1"}`
	if got != want {
		t.Fatalf("unexpected canonical trust model bytes:\nwant: %s\ngot:  %s", want, got)
	}

	gotDigest, err := TrustModelPayloadDigest(claims)
	if err != nil {
		t.Fatalf("trust model payload digest: %v", err)
	}
	wantDigest := "sha256:5963c8bbb9834c72833ad3023c32031d6f73fa10112645c978339139272bc82f"
	if gotDigest != wantDigest {
		t.Fatalf("unexpected trust model payload digest: want %s got %s", wantDigest, gotDigest)
	}
}

func TestVerifyDetachedEnvelope(t *testing.T) {
	t.Parallel()

	seed := []byte("01234567890123456789012345678901")
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	canonical := CanonicalWorkloadIdentityBindingBytes(WorkloadIdentityBindingClaims{
		Subject: WorkloadIdentitySubjectClaims{
			ArtifactClass:        "service",
			ArtifactDigest:       "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			DerivationSpecDigest: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
			OutputID:             "runtime",
			PolicyVersion:        "2026-03-31",
		},
		Descriptor: WorkloadDescriptorClaims{
			WorkloadType:       "service",
			ModulePath:         "services.execution.ExecutionServer",
			ServiceName:        "execution",
			TargetPlatform:     "docker",
			Description:        "Execution workload",
			WorkloadIdentityID: "spiffe://monolith.internal/service/execution",
		},
	})
	envelope := DetachedEnvelope{
		PayloadDigest:    digestBytes(canonical),
		CanonicalSpecB64: base64.StdEncoding.EncodeToString(canonical),
		SignatureValue:   base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical)),
		KeyID:            "ags-signing-key-v1",
		Algorithm:        "ed25519",
	}

	if err := VerifyDetachedEnvelope(canonical, envelope, "ags-signing-key-v1", "ed25519", publicKey); err != nil {
		t.Fatalf("verify detached envelope: %v", err)
	}

	envelope.PayloadDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if err := VerifyDetachedEnvelope(canonical, envelope, "ags-signing-key-v1", "ed25519", publicKey); err == nil || err.Error() != "payload digest mismatch" {
		t.Fatalf("expected payload digest mismatch, got %v", err)
	}
}
