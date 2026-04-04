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
						Principal: "spiffe://monolith.internal/service/deployment",
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
						ProducerRunID:        "build-run-1",
						PolicyVersion:        "2026-03-31",
						ExpectedArtifactType: "static-script",
						Constraints: DerivationConstraints{
							AllowedToolchains:      []string{"go", "bash"},
							ForbiddenToolchains:    []string{"python"},
							OS:                     "linux",
							Arch:                   "amd64",
							WritablePaths:          []string{"/tmp", "/workspace"},
							ForbiddenPaths:         []string{"/root"},
							DeterminismExpectation: "deterministic",
						},
					},
					WorkloadBinding: WorkloadBinding{
						ModulePath:    "services.execution.ExecutionServer",
						PolicyVersion: "2026-03-31",
					},
				},
				Execution: ExecutionClaims{
					Runtime: ExecutionRuntime{
						Parameters:           []string{"z", "a"},
						EnvironmentVariables: []string{"APP_MODE", "API_URL"},
						RequiredCapabilities: []string{"b", "a"},
					},
					Workload: ExecutionWorkload{
						ArtifactClass:      "service",
						WorkloadType:       "service",
						ServiceName:        "execution",
						TargetPlatform:     "docker",
						Description:        "Execution workload",
						WorkloadIdentityID: "spiffe://monolith.internal/service/execution",
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
	if !strings.Contains(canonicalString, `"execution":{"runtime"`) {
		t.Fatalf("expected canonical bytes to encode admission execution claims: %s", canonicalString)
	}
	if strings.Contains(canonicalString, `"admission":{"runtime"`) {
		t.Fatalf("expected canonical bytes to omit the old mixed admission runtime shape: %s", canonicalString)
	}
}

func TestValidateRejectsPolicyVersionMismatch(t *testing.T) {
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
						Principal: "spiffe://monolith.internal/service/deployment",
					},
					BuildLogDigest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
				},
			},
			Admission: AdmissionClaims{
				Authorization: AuthorizationClaims{
					Derivation: DerivationAuthorization{
						DerivationSpecDigest: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
						OutputID:             "runtime",
						ProducerRunID:        "build-run-1",
						PolicyVersion:        "policy-a",
						Constraints: DerivationConstraints{
							OS:   "linux",
							Arch: "amd64",
						},
					},
					WorkloadBinding: WorkloadBinding{
						ModulePath:    "services.execution.ExecutionServer",
						PolicyVersion: "policy-b",
					},
				},
				Execution: ExecutionClaims{
					Workload: ExecutionWorkload{
						ArtifactClass:      "service",
						WorkloadType:       "service",
						ServiceName:        "execution",
						WorkloadIdentityID: "spiffe://monolith.internal/service/execution",
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

	if err := record.Validate(); err == nil || !strings.Contains(err.Error(), "policy_version") {
		t.Fatalf("expected policy version mismatch error, got %v", err)
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
