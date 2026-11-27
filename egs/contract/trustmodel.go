package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// RuntimeTrustPolicy is the signed runtime trust payload that EGS publishes
// and ES enforces. It intentionally carries only signer and artifact trust
// policy, not broader publication metadata.
type RuntimeTrustPolicy struct {
	SignerPolicy   SignerPolicy   `json:"signer_policy"`
	ArtifactPolicy ArtifactPolicy `json:"artifact_policy"`
}

// PublicationMetadata is EGS-owned control-plane metadata published alongside
// runtime trust. It is intentionally outside the signed runtime trust payload.
type PublicationMetadata struct {
	Version        string `json:"version"`
	UpdateRevision int    `json:"update_revision"`
}

type SignerPolicy struct {
	AllowedSigners []string `json:"allowed_signers"`
	RevokedSigners []string `json:"revoked_signers"`
}

type ArtifactPolicy struct {
	RevokedArtifacts []string `json:"revoked_artifacts"`
}

func (m RuntimeTrustPolicy) Validate() error {
	if err := validateUniqueStrings("runtime_trust.signer_policy.allowed_signers", m.SignerPolicy.AllowedSigners); err != nil {
		return err
	}
	if err := validateUniqueStrings("runtime_trust.signer_policy.revoked_signers", m.SignerPolicy.RevokedSigners); err != nil {
		return err
	}
	if err := validateUniqueStrings("runtime_trust.artifact_policy.revoked_artifacts", m.ArtifactPolicy.RevokedArtifacts); err != nil {
		return err
	}
	for _, digest := range m.ArtifactPolicy.RevokedArtifacts {
		if !isLabeledSHA256Digest(digest) {
			return fmt.Errorf("runtime_trust.artifact_policy.revoked_artifacts must contain labeled sha256 digests in lower-case hex (sha256: and 64 lower-case hex characters); got %q", digest)
		}
	}
	return nil
}

func (m RuntimeTrustPolicy) Normalized() RuntimeTrustPolicy {
	return RuntimeTrustPolicy{
		SignerPolicy: SignerPolicy{
			AllowedSigners: normalizeStrings(m.SignerPolicy.AllowedSigners),
			RevokedSigners: normalizeStrings(m.SignerPolicy.RevokedSigners),
		},
		ArtifactPolicy: ArtifactPolicy{
			RevokedArtifacts: normalizeStrings(m.ArtifactPolicy.RevokedArtifacts),
		},
	}
}

// CanonicalBytes returns the signed runtime trust payload. EGS-owned
// publication metadata is intentionally excluded.
func (m RuntimeTrustPolicy) CanonicalBytes() ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}

	normalized := m.Normalized()
	payload := struct {
		ArtifactPolicy struct {
			RevokedArtifacts []string `json:"revoked_artifacts"`
		} `json:"artifact_policy"`
		SignerPolicy struct {
			AllowedSigners []string `json:"allowed_signers"`
			RevokedSigners []string `json:"revoked_signers"`
		} `json:"signer_policy"`
	}{}
	payload.ArtifactPolicy.RevokedArtifacts = append([]string(nil), normalized.ArtifactPolicy.RevokedArtifacts...)
	payload.SignerPolicy.AllowedSigners = append([]string(nil), normalized.SignerPolicy.AllowedSigners...)
	payload.SignerPolicy.RevokedSigners = append([]string(nil), normalized.SignerPolicy.RevokedSigners...)

	return json.Marshal(payload)
}

func (m RuntimeTrustPolicy) PayloadDigest() (string, error) {
	canonical, err := m.CanonicalBytes()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func (m PublicationMetadata) Validate() error {
	if strings.TrimSpace(m.Version) == "" {
		return fmt.Errorf("publication.version is required")
	}
	if m.UpdateRevision <= 0 {
		return fmt.Errorf("publication.update_revision must be greater than 0")
	}
	return nil
}

func (m PublicationMetadata) Normalized() PublicationMetadata {
	return PublicationMetadata{
		Version:        strings.TrimSpace(m.Version),
		UpdateRevision: m.UpdateRevision,
	}
}

func normalizeStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}

	normalized := make([]string, 0, len(values))
	for _, value := range values {
		normalized = append(normalized, strings.TrimSpace(value))
	}
	slices.Sort(normalized)
	return normalized
}

func validateUniqueStrings(field string, values []string) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			return fmt.Errorf("%s cannot contain empty values", field)
		}
		if _, exists := seen[trimmed]; exists {
			return fmt.Errorf("%s cannot contain duplicate values", field)
		}
		seen[trimmed] = struct{}{}
	}
	return nil
}

// labeledSHA256Digest is the only digest spelling ES accepts in a request
// (es/admission/service.go). A revoked-artifact entry in any other spelling,
// upper-case hex included, would never equal a request's digest, so it would
// revoke nothing; EGS refuses it instead of normalizing it, so that the
// operator sees the mistake.
var labeledSHA256Digest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func isLabeledSHA256Digest(value string) bool {
	return labeledSHA256Digest.MatchString(value)
}
