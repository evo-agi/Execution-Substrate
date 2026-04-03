package signingv2

func CanonicalDerivationAttestationPayload(payload DerivationAttestationPayload) ([]byte, error) {
	policy := map[string]any{
		"version": payload.Claims.Policy.Version,
	}
	if payload.Claims.Policy.ExpectedArtifactType != "" {
		policy["expected_artifact_type"] = payload.Claims.Policy.ExpectedArtifactType
	}

	return canonicalJSON(map[string]any{
		"claims": map[string]any{
			"constraints": map[string]any{
				"allowed_toolchains":      normalizeStringSet(payload.Claims.Constraints.AllowedToolchains),
				"arch":                    payload.Claims.Constraints.Arch,
				"determinism_expectation": payload.Claims.Constraints.DeterminismExpectation,
				"forbidden_paths":         normalizeStringSet(payload.Claims.Constraints.ForbiddenPaths),
				"forbidden_toolchains":    normalizeStringSet(payload.Claims.Constraints.ForbiddenToolchains),
				"network_access":          payload.Claims.Constraints.NetworkAccess,
				"os":                      payload.Claims.Constraints.OS,
				"writable_paths":          normalizeStringSet(payload.Claims.Constraints.WritablePaths),
			},
			"policy": policy,
		},
		"kind": KindDerivationAttestation,
		"subject": map[string]any{
			"artifact_digest":        payload.Subject.ArtifactDigest,
			"derivation_spec_digest": payload.Subject.DerivationSpecDigest,
			"output_id":              payload.Subject.OutputID,
		},
	})
}
