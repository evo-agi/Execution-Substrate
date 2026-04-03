package signingv1

import (
	"encoding/json"
	"slices"
)

func CanonicalTrustModelBytes(claims TrustModelClaims) ([]byte, error) {
	allowed := append([]string(nil), normalizeStrings(claims.AllowedSigners)...)
	revoked := append([]string(nil), normalizeStrings(claims.RevokedSigners)...)
	artifacts := append([]string(nil), normalizeStrings(claims.RevokedArtifacts)...)
	slices.Sort(allowed)
	slices.Sort(revoked)
	slices.Sort(artifacts)

	payload := struct {
		ArtifactPolicy struct {
			RevokedArtifacts []string `json:"revoked_artifacts"`
		} `json:"artifact_policy"`
		SignerPolicy struct {
			AllowedSigners []string `json:"allowed_signers"`
			RevokedSigners []string `json:"revoked_signers"`
		} `json:"signer_policy"`
		UpdateRevision int    `json:"update_revision"`
		Version        string `json:"version"`
	}{
		UpdateRevision: claims.UpdateRevision,
		Version:        claims.Version,
	}
	payload.ArtifactPolicy.RevokedArtifacts = artifacts
	payload.SignerPolicy.AllowedSigners = allowed
	payload.SignerPolicy.RevokedSigners = revoked

	return json.Marshal(payload)
}

func TrustModelPayloadDigest(claims TrustModelClaims) (string, error) {
	canonical, err := CanonicalTrustModelBytes(claims)
	if err != nil {
		return "", err
	}
	return digestBytes(canonical), nil
}
