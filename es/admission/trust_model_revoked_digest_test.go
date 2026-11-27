package admission

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	egscontract "execution-substrate/egs/contract"
)

// An EGS older than the lower-case rule accepts a revoked-artifact digest in
// upper-case hex and signs it. Such an entry would never match a request's
// digest, so it would revoke nothing. On a host where only ES is upgraded
// (the Remote Alpha ES upgrade does not replace EGS), ES's own check is what
// refuses it. These cases serve a correctly signed model from a synthetic EGS
// and check that ES refuses it before installing it.
func TestFetchVerifiedTrustModelRefusesARevokedArtifactNotInLowerCaseHex(t *testing.T) {
	lower := "sha256:" + strings.Repeat("abcdef0123456789", 4)
	cases := []struct {
		name  string
		entry string
	}{
		{"upper-case hex", "sha256:" + strings.ToUpper(strings.TrimPrefix(lower, "sha256:"))},
		{"one upper-case hex", lower[:len(lower)-1] + "F"},
		{"upper-case label", "SHA256:" + strings.TrimPrefix(lower, "sha256:")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newRevokedDigestTrustModelService(t, tc.entry).fetchVerifiedTrustModel(context.Background())
			want := "validate trust model: " + egscontract.RuntimeTrustPolicy{ArtifactPolicy: egscontract.ArtifactPolicy{RevokedArtifacts: []string{tc.entry}}}.Validate().Error()
			if err == nil || err.Error() != want {
				t.Fatalf("fetchVerifiedTrustModel() = %v, want %q", err, want)
			}
		})
	}

	// Control: the same construction with a lower-case entry verifies and is
	// installed, so the refusals above come from the spelling check and not
	// from the signature.
	t.Run("lower-case hex is installed", func(t *testing.T) {
		got, err := newRevokedDigestTrustModelService(t, lower).fetchVerifiedTrustModel(context.Background())
		if err != nil {
			t.Fatalf("fetchVerifiedTrustModel() = %v, want nil", err)
		}
		if len(got.ArtifactPolicy.RevokedArtifacts) != 1 || got.ArtifactPolicy.RevokedArtifacts[0] != lower {
			t.Fatalf("revoked artifacts = %q, want [%q]", got.ArtifactPolicy.RevokedArtifacts, lower)
		}
	})
}

// newRevokedDigestTrustModelService returns a Service whose EGS serves a model
// that revokes entry, signed the way an EGS that accepts entry would sign it.
// CanonicalBytes refuses an entry the contract refuses, so the signed bytes
// are built here in the same shape; for a lower-case entry the test checks
// that they equal CanonicalBytes.
func newRevokedDigestTrustModelService(t *testing.T, entry string) *Service {
	t.Helper()
	trust := egscontract.RuntimeTrustPolicy{
		SignerPolicy:   egscontract.SignerPolicy{AllowedSigners: []string{"k1"}, RevokedSigners: []string{}},
		ArtifactPolicy: egscontract.ArtifactPolicy{RevokedArtifacts: []string{entry}},
	}
	payload := struct {
		ArtifactPolicy struct {
			RevokedArtifacts []string `json:"revoked_artifacts"`
		} `json:"artifact_policy"`
		SignerPolicy struct {
			AllowedSigners []string `json:"allowed_signers"`
			RevokedSigners []string `json:"revoked_signers"`
		} `json:"signer_policy"`
	}{}
	payload.ArtifactPolicy.RevokedArtifacts = []string{entry}
	payload.SignerPolicy.AllowedSigners = []string{"k1"}
	canonical, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal canonical payload: %v", err)
	}
	if trust.Validate() == nil {
		want, err := trust.CanonicalBytes()
		if err != nil || string(want) != string(canonical) {
			t.Fatalf("test canonical bytes %s differ from CanonicalBytes %s (%v)", canonical, want, err)
		}
	}

	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	body, err := json.Marshal(signedRuntimeTrustResponse{
		RuntimeTrust:  trust,
		Algorithm:     "ed25519",
		KeyID:         "synthetic-egs",
		PayloadDigest: digestBytes(canonical),
		Signature:     base64.StdEncoding.EncodeToString(ed25519.Sign(private, canonical)),
	})
	if err != nil {
		t.Fatalf("marshal trust model response: %v", err)
	}
	service := &Service{trustModelVerifier: &ed25519Verifier{algorithm: "ed25519", keyID: "synthetic-egs", publicKey: public}}
	service.egsClient = newResolvedPlanDependencyClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/trust-model" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	service.egsClient.client.Timeout = 5 * time.Second
	return service
}
