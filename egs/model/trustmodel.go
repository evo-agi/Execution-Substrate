package model

import (
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	signingv1 "execution-platform/legacy/contracts/signing/v1"
)

type TrustModel struct {
	SignerPolicy   SignerPolicy   `json:"signer_policy"`
	ArtifactPolicy ArtifactPolicy `json:"artifact_policy"`
	UpdateRevision int            `json:"update_revision"`
	Version        string         `json:"version"`
}

type SignerPolicy struct {
	AllowedSigners []string `json:"allowed_signers"`
	RevokedSigners []string `json:"revoked_signers"`
}

type ArtifactPolicy struct {
	RevokedArtifacts []string `json:"revoked_artifacts"`
}

func (m TrustModel) Validate() error {
	if strings.TrimSpace(m.Version) == "" {
		return fmt.Errorf("trust_model.version is required")
	}
	if m.UpdateRevision <= 0 {
		return fmt.Errorf("trust_model.update_revision must be greater than 0")
	}
	if err := validateUniqueStrings("trust_model.signer_policy.allowed_signers", m.SignerPolicy.AllowedSigners); err != nil {
		return err
	}
	if err := validateUniqueStrings("trust_model.signer_policy.revoked_signers", m.SignerPolicy.RevokedSigners); err != nil {
		return err
	}
	if err := validateUniqueStrings("trust_model.artifact_policy.revoked_artifacts", m.ArtifactPolicy.RevokedArtifacts); err != nil {
		return err
	}
	for _, digest := range m.ArtifactPolicy.RevokedArtifacts {
		if !isLabeledSHA256Digest(digest) {
			return fmt.Errorf("trust_model.artifact_policy.revoked_artifacts must contain labeled sha256 digests")
		}
	}
	return nil
}

func (m TrustModel) Normalized() TrustModel {
	normalized := TrustModel{
		UpdateRevision: m.UpdateRevision,
		Version:        strings.TrimSpace(m.Version),
		SignerPolicy: SignerPolicy{
			AllowedSigners: normalizeStrings(m.SignerPolicy.AllowedSigners),
			RevokedSigners: normalizeStrings(m.SignerPolicy.RevokedSigners),
		},
		ArtifactPolicy: ArtifactPolicy{
			RevokedArtifacts: normalizeStrings(m.ArtifactPolicy.RevokedArtifacts),
		},
	}
	return normalized
}

// CanonicalBytes returns the versioned signed payload for the TrustModel.
//
// trust_model.version is authoritative for signature semantics. In the current
// EGS v1 contract, only canonical TrustModel fields are included here. Response
// metadata such as source_digest is intentionally excluded and is not
// authenticated in v1. ES and other consumers must ignore source_digest for
// trust decisions in v1; only payload_digest and signature are authoritative.
func (m TrustModel) CanonicalBytes() ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}

	normalized := m.Normalized()
	return signingv1.CanonicalTrustModelBytes(signingv1.TrustModelClaims{
		AllowedSigners:   append([]string(nil), normalized.SignerPolicy.AllowedSigners...),
		RevokedSigners:   append([]string(nil), normalized.SignerPolicy.RevokedSigners...),
		RevokedArtifacts: append([]string(nil), normalized.ArtifactPolicy.RevokedArtifacts...),
		UpdateRevision:   normalized.UpdateRevision,
		Version:          normalized.Version,
	})
}

func (m TrustModel) PayloadDigest() (string, error) {
	if err := m.Validate(); err != nil {
		return "", err
	}

	normalized := m.Normalized()
	digest, err := signingv1.TrustModelPayloadDigest(signingv1.TrustModelClaims{
		AllowedSigners:   append([]string(nil), normalized.SignerPolicy.AllowedSigners...),
		RevokedSigners:   append([]string(nil), normalized.SignerPolicy.RevokedSigners...),
		RevokedArtifacts: append([]string(nil), normalized.ArtifactPolicy.RevokedArtifacts...),
		UpdateRevision:   normalized.UpdateRevision,
		Version:          normalized.Version,
	})
	if err != nil {
		return "", err
	}
	return digest, nil
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

func isLabeledSHA256Digest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") {
		return false
	}
	hexPart := strings.TrimPrefix(value, "sha256:")
	if len(hexPart) != 64 {
		return false
	}
	_, err := hex.DecodeString(hexPart)
	return err == nil
}
