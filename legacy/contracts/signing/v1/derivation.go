package signingv1

import "encoding/json"

func CanonicalDerivationAttestationBytes(claims DerivationAttestationClaims) []byte {
	payload := struct {
		ArtifactDigest       string                      `json:"artifact_digest"`
		DerivationSpecDigest string                      `json:"derivation_spec_digest"`
		OutputID             string                      `json:"output_id"`
		Constraints          DerivationConstraintsClaims `json:"constraints"`
		PolicyVersion        string                      `json:"policy_version"`
		ExpectedArtifactType string                      `json:"expected_artifact_type,omitempty"`
	}{
		ArtifactDigest:       claims.Subject.ArtifactDigest,
		DerivationSpecDigest: claims.Subject.DerivationSpecDigest,
		OutputID:             claims.Subject.OutputID,
		Constraints:          claims.Constraints,
		PolicyVersion:        claims.Policy.Version,
		ExpectedArtifactType: claims.Policy.ExpectedArtifactType,
	}
	encoded, _ := json.Marshal(payload)
	return encoded
}
