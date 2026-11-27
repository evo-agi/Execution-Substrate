package contract_test

import (
	"os"
	"strings"
	"testing"

	"execution-substrate/egs/contract"
)

const validDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// The revocation runbook (.runbooks/system/Governed Execution ES Revoke An
// Artifact Or Signer.md) tells the operator that EGS refuses to start on these
// entries. These tests pin the contract check; egs/app's
// TestEGSRefusesToStartOnEntriesTheRevocationRunbookWarnsAbout pins that EGS's
// start path runs it.
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
			name:   "artifact digest of 63 hex characters",
			policy: contract.RuntimeTrustPolicy{ArtifactPolicy: contract.ArtifactPolicy{RevokedArtifacts: []string{validDigest[:len(validDigest)-1]}}},
			want:   "runtime_trust.artifact_policy.revoked_artifacts must contain labeled sha256 digests",
		},
		// An even number of hex characters other than 64 passes a hex decode,
		// so these two pin the length rule on its own.
		{
			name:   "artifact digest of 62 hex characters",
			policy: contract.RuntimeTrustPolicy{ArtifactPolicy: contract.ArtifactPolicy{RevokedArtifacts: []string{validDigest[:len(validDigest)-2]}}},
			want:   "runtime_trust.artifact_policy.revoked_artifacts must contain labeled sha256 digests",
		},
		{
			name:   "artifact digest of 66 hex characters",
			policy: contract.RuntimeTrustPolicy{ArtifactPolicy: contract.ArtifactPolicy{RevokedArtifacts: []string{validDigest + "ab"}}},
			want:   "runtime_trust.artifact_policy.revoked_artifacts must contain labeled sha256 digests",
		},
		// 64 characters that are not hex pin the hex rule on its own.
		{
			name:   "artifact digest of 64 characters that are not hex",
			policy: contract.RuntimeTrustPolicy{ArtifactPolicy: contract.ArtifactPolicy{RevokedArtifacts: []string{"sha256:" + strings.Repeat("g", 64)}}},
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

const revocationRunbookPath = "../../.runbooks/system/Governed Execution ES Revoke An Artifact Or Signer.md"

// ES accepts a request's digest only in lower-case hex and compares revoked
// digests as exact text. The runbook's note says what EGS does with an
// upper-case digest; this test keeps that note equal to what the contract
// check does, so a change to the check changes the note in the same change.
func TestRevocationRunbookNoteOnUpperCaseDigestsMatchesEGS(t *testing.T) {
	data, err := os.ReadFile(revocationRunbookPath)
	if err != nil {
		t.Fatalf("read runbook: %v", err)
	}
	runbook := string(data)
	const accepts = "EGS accepts upper-case hex in a digest"
	const refuses = "EGS refuses upper-case hex in a digest"
	upper := contract.RuntimeTrustPolicy{ArtifactPolicy: contract.ArtifactPolicy{RevokedArtifacts: []string{"sha256:" + strings.Repeat("AB", 32)}}}
	if upper.Validate() == nil {
		if !strings.Contains(runbook, accepts) || strings.Contains(runbook, refuses) {
			t.Fatalf("EGS accepts an upper-case digest, so the runbook must say %q and not %q", accepts, refuses)
		}
		return
	}
	if !strings.Contains(runbook, refuses) || strings.Contains(runbook, accepts) {
		t.Fatalf("EGS refuses an upper-case digest, so the runbook must say %q and not %q", refuses, accepts)
	}
}
