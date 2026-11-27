package contract_test

import (
	"strings"
	"testing"

	"execution-substrate/egs/contract"
)

const validDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// The revocation runbook (.runbooks/system/Governed Execution ES Revoke An
// Artifact Or Signer.md) tells the operator that EGS refuses to start on these
// entries. These tests pin that refusal.
func TestRuntimeTrustPolicyRefusesEntriesTheRevocationRunbookWarnsAbout(t *testing.T) {
	cases := []struct {
		name   string
		policy contract.RuntimeTrustPolicy
		want   string
	}{
		{
			name:   "artifact digest without its label",
			policy: contract.RuntimeTrustPolicy{ArtifactPolicy: contract.ArtifactPolicy{RevokedArtifacts: []string{strings.TrimPrefix(validDigest, "sha256:")}}},
			want:   "runtime_trust.artifact_policy.revoked_artifacts must contain labeled sha256 digests",
		},
		{
			name:   "artifact digest that is too short",
			policy: contract.RuntimeTrustPolicy{ArtifactPolicy: contract.ArtifactPolicy{RevokedArtifacts: []string{validDigest[:len(validDigest)-1]}}},
			want:   "runtime_trust.artifact_policy.revoked_artifacts must contain labeled sha256 digests",
		},
		{
			name:   "duplicate revoked artifact",
			policy: contract.RuntimeTrustPolicy{ArtifactPolicy: contract.ArtifactPolicy{RevokedArtifacts: []string{validDigest, validDigest}}},
			want:   "runtime_trust.artifact_policy.revoked_artifacts cannot contain duplicate values",
		},
		{
			name:   "duplicate revoked signer",
			policy: contract.RuntimeTrustPolicy{SignerPolicy: contract.SignerPolicy{RevokedSigners: []string{"k1", " k1 "}}},
			want:   "runtime_trust.signer_policy.revoked_signers cannot contain duplicate values",
		},
		{
			name:   "empty revoked signer",
			policy: contract.RuntimeTrustPolicy{SignerPolicy: contract.SignerPolicy{RevokedSigners: []string{"  "}}},
			want:   "runtime_trust.signer_policy.revoked_signers cannot contain empty values",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.policy.Validate()
			if err == nil || err.Error() != tc.want {
				t.Fatalf("Validate() = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestRuntimeTrustPolicyAcceptsARevokedArtifactAndARevokedSigner(t *testing.T) {
	policy := contract.RuntimeTrustPolicy{
		SignerPolicy:   contract.SignerPolicy{AllowedSigners: []string{"k1"}, RevokedSigners: []string{"k1"}},
		ArtifactPolicy: contract.ArtifactPolicy{RevokedArtifacts: []string{validDigest}},
	}
	if err := policy.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}
