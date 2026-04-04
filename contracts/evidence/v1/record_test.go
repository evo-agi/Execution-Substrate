package evidencev1

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

func TestCanonicalBytesNormalizeSlicesAndVerifySeal(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	identity, err := NewArtifactIdentity(
		"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"static-script",
		"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	)
	if err != nil {
		t.Fatalf("new artifact identity: %v", err)
	}

	record := ArtifactEvidence{
		Claims: Claims{
			SchemaVersion: Version,
			Package: PackageClaims{
				Identity: identity,
				Publication: Publication{
					BuilderService: "artifact-governance",
					Invoker: Invoker{
						Service:   "deployment",
						Principal: "spiffe://execution.internal/service/deployment",
					},
					PolicyDecisions: []PolicyDecision{
						{Rule: "z-last", Result: "allow"},
						{Rule: "a-first", Result: "allow"},
					},
					BuildLogDigest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
				},
			},
			Admission: AdmissionClaims{
				Authorization: AuthorizationClaims{
					Derivation: DerivationAuthorization{
						DerivationSpecDigest: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
						OutputID:             "runtime",
					},
				},
				Execution: ExecutionClaims{
					Runtime: ExecutionRuntime{
						EnvironmentVariables: []string{"APP_MODE", "API_URL"},
						RequiredCapabilities: []string{"b", "a"},
					},
					Workload: ExecutionWorkload{
						TargetPlatform: "docker",
					},
					Access: ExecutionAccess{
						NetworkAccess: true,
					},
				},
			},
		},
	}

	canonical, err := record.CanonicalBytes()
	if err != nil {
		t.Fatalf("canonicalize record: %v", err)
	}

	signed := record
	signed.Seal = NewSeal(canonical, "ags-artifact-signer", "ed25519", base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical)))

	if err := Verify(signed, "ags-artifact-signer", "ed25519", publicKey); err != nil {
		t.Fatalf("verify record: %v", err)
	}

	canonicalString := string(canonical)
	if strings.Index(canonicalString, `"rule":"a-first"`) > strings.Index(canonicalString, `"rule":"z-last"`) {
		t.Fatalf("expected policy decisions to be sorted in canonical bytes: %s", canonicalString)
	}
	if strings.Index(canonicalString, `"required_capabilities":["a","b"]`) == -1 {
		t.Fatalf("expected required_capabilities to be sorted in canonical bytes: %s", canonicalString)
	}
	if !strings.Contains(canonicalString, `"authorization":{"derivation"`) {
		t.Fatalf("expected canonical bytes to encode admission authorization claims: %s", canonicalString)
	}
	if strings.Contains(canonicalString, `"workload_binding"`) {
		t.Fatalf("expected canonical bytes to omit workload binding from authorization claims: %s", canonicalString)
	}
	if strings.Contains(canonicalString, `"producer_run_id"`) || strings.Contains(canonicalString, `"policy_version"`) || strings.Contains(canonicalString, `"expected_artifact_type"`) || strings.Contains(canonicalString, `"constraints"`) {
		t.Fatalf("expected canonical bytes to omit removed authorization residue: %s", canonicalString)
	}
	if !strings.Contains(canonicalString, `"execution":{"runtime"`) {
		t.Fatalf("expected canonical bytes to encode admission execution claims: %s", canonicalString)
	}
	if strings.Contains(canonicalString, `"parameters"`) || strings.Contains(canonicalString, `"workload_identity_id"`) || strings.Contains(canonicalString, `"service_name"`) || strings.Contains(canonicalString, `"artifact_class"`) || strings.Contains(canonicalString, `"workload_type"`) || strings.Contains(canonicalString, `"description"`) {
		t.Fatalf("expected canonical bytes to omit removed execution metadata: %s", canonicalString)
	}
	if strings.Contains(canonicalString, `"admission":{"runtime"`) {
		t.Fatalf("expected canonical bytes to omit the old mixed admission runtime shape: %s", canonicalString)
	}
}

func TestValidateRejectsMissingAuthorizationOutputID(t *testing.T) {
	identity, err := NewArtifactIdentity(
		"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"static-script",
		"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	)
	if err != nil {
		t.Fatalf("new artifact identity: %v", err)
	}

	record := ArtifactEvidence{
		Claims: Claims{
			SchemaVersion: Version,
			Package: PackageClaims{
				Identity: identity,
				Publication: Publication{
					BuilderService: "artifact-governance",
					Invoker: Invoker{
						Service:   "deployment",
						Principal: "spiffe://execution.internal/service/deployment",
					},
					BuildLogDigest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
				},
			},
			Admission: AdmissionClaims{
				Authorization: AuthorizationClaims{
					Derivation: DerivationAuthorization{
						DerivationSpecDigest: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
					},
				},
				Execution: ExecutionClaims{
					Workload: ExecutionWorkload{
						TargetPlatform: "docker",
					},
				},
			},
		},
		Seal: Seal{
			Algorithm:     "ed25519",
			KeyID:         "ags-artifact-signer",
			ContentDigest: "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			Signature:     "ZmFrZQ==",
		},
	}

	if err := record.Validate(); err == nil || !strings.Contains(err.Error(), "output_id") {
		t.Fatalf("expected missing output_id error, got %v", err)
	}
}

func TestDeriveArtifactDigestUsesPackageIdentityOnly(t *testing.T) {
	first, err := DeriveArtifactDigest(
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"static-script",
		"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	)
	if err != nil {
		t.Fatalf("derive artifact digest: %v", err)
	}

	second, err := DeriveArtifactDigest(
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"static-script",
		"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	)
	if err != nil {
		t.Fatalf("derive artifact digest again: %v", err)
	}
	if first != second {
		t.Fatalf("expected identical package identity inputs to produce stable artifact digests, got %q and %q", first, second)
	}

	changedIntent, err := DeriveArtifactDigest(
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"static-script",
		"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	)
	if err != nil {
		t.Fatalf("derive artifact digest with changed intent: %v", err)
	}
	if first == changedIntent {
		t.Fatalf("expected intent digest to affect artifact identity, both were %q", first)
	}
}
