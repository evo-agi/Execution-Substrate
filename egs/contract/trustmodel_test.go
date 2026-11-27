package contract_test

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"execution-substrate/egs/contract"
)

const validDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// refusedDigest is EGS's refusal of a revoked-artifact entry, which names the
// entry so that the journal shows which one to fix.
func refusedDigest(entry string) string {
	return fmt.Sprintf("runtime_trust.artifact_policy.revoked_artifacts must contain labeled sha256 digests in lower-case hex (sha256: and 64 lower-case hex characters); got %q", entry)
}

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
			want:   refusedDigest(strings.TrimPrefix(validDigest, "sha256:")),
		},
		{
			name:   "artifact digest of 63 hex characters",
			policy: contract.RuntimeTrustPolicy{ArtifactPolicy: contract.ArtifactPolicy{RevokedArtifacts: []string{validDigest[:len(validDigest)-1]}}},
			want:   refusedDigest(validDigest[:len(validDigest)-1]),
		},
		// An even number of hex characters other than 64 passes a hex decode,
		// so these two pin the length rule on its own.
		{
			name:   "artifact digest of 62 hex characters",
			policy: contract.RuntimeTrustPolicy{ArtifactPolicy: contract.ArtifactPolicy{RevokedArtifacts: []string{validDigest[:len(validDigest)-2]}}},
			want:   refusedDigest(validDigest[:len(validDigest)-2]),
		},
		{
			name:   "artifact digest of 66 hex characters",
			policy: contract.RuntimeTrustPolicy{ArtifactPolicy: contract.ArtifactPolicy{RevokedArtifacts: []string{validDigest + "ab"}}},
			want:   refusedDigest(validDigest + "ab"),
		},
		// ES admits a digest only in lower-case hex, so an upper-case entry
		// would never match a request.
		{
			name:   "artifact digest in upper-case hex",
			policy: contract.RuntimeTrustPolicy{ArtifactPolicy: contract.ArtifactPolicy{RevokedArtifacts: []string{"sha256:" + strings.ToUpper(strings.TrimPrefix(validDigest, "sha256:"))}}},
			want:   refusedDigest("sha256:" + strings.ToUpper(strings.TrimPrefix(validDigest, "sha256:"))),
		},
		// 64 characters that are not hex pin the hex rule on its own.
		{
			name:   "artifact digest of 64 characters that are not hex",
			policy: contract.RuntimeTrustPolicy{ArtifactPolicy: contract.ArtifactPolicy{RevokedArtifacts: []string{"sha256:" + strings.Repeat("g", 64)}}},
			want:   refusedDigest("sha256:" + strings.Repeat("g", 64)),
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
// digests as exact text. What EGS does with an upper-case digest decides which
// note the runbook must carry; the other lines that mention upper case must
// hold either way. This test keeps every line of the runbook's procedure (all
// of it before "## Test Evidence", which records what ran) that mentions upper
// case equal to one of these, so a change to the check changes the runbook in
// the same change.
const (
	runbookUpperCaseNoteWhenEGSAccepts = "- EGS accepts upper-case hex in a digest, but ES compares the exact text, so an upper-case entry would pass EGS and never match an artifact. Step 2 accepts lower-case only."
	runbookUpperCaseNoteWhenEGSRefuses = "- EGS refuses upper-case hex in a digest, as step 2 does: ES compares the exact text, so an upper-case entry could never match an artifact."
)

var runbookUpperCaseLinesEitherWay = []string{
	"To find the problems in the lists without showing any other field, run the check below. It also flags a digest in upper-case hex, which ES would never match.",
}

// Failure-table row 1 names the only spelling ES matches, whatever EGS does.
const runbookRefusedDigestRow = "| Step 2 exits with \"an artifact digest is sha256: followed by 64 lowercase hex characters\" | The value is not `sha256:` and 64 lower-case hex characters, the only spelling ES matches | Copy the `artifact_digest` from the publish response; nothing was changed |"

func TestRevocationRunbookNoteOnUpperCaseDigestsMatchesEGS(t *testing.T) {
	data, err := os.ReadFile(revocationRunbookPath)
	if err != nil {
		t.Fatalf("read runbook: %v", err)
	}
	lines := strings.Split(string(data), "\n")
	evidence := slices.Index(lines, "## Test Evidence")
	if evidence < 0 || slices.Index(lines[evidence+1:], "## Test Evidence") >= 0 {
		t.Fatal(`the runbook must have exactly one "## Test Evidence" heading`)
	}
	procedure := lines[:evidence]

	upper := contract.RuntimeTrustPolicy{ArtifactPolicy: contract.ArtifactPolicy{RevokedArtifacts: []string{"sha256:" + strings.Repeat("AB", 32)}}}
	what, note := "accepts", runbookUpperCaseNoteWhenEGSAccepts
	if upper.Validate() != nil {
		what, note = "refuses", runbookUpperCaseNoteWhenEGSRefuses
	}
	allowed := append([]string{note}, runbookUpperCaseLinesEitherWay...)

	count := func(want string) int {
		n := 0
		for _, line := range procedure {
			if line == want {
				n++
			}
		}
		return n
	}
	for _, want := range allowed {
		if got := count(want); got != 1 {
			t.Errorf("EGS %s an upper-case digest, so the runbook's procedure must hold this line exactly once, found %d times:\n%s", what, got, want)
		}
	}
	if got := count(runbookRefusedDigestRow); got != 1 {
		t.Errorf("the runbook's procedure must hold failure-table row 1 exactly once, found %d times:\n%s", got, runbookRefusedDigestRow)
	}
	for number, line := range procedure {
		if !strings.Contains(strings.ToLower(line), "upper") || slices.Contains(allowed, line) {
			continue
		}
		t.Errorf("runbook line %d mentions upper case but is not one of the lines this test allows while EGS %s an upper-case digest; make it hold either way and add it to runbookUpperCaseLinesEitherWay, or remove it:\n%s", number+1, what, line)
	}
}
