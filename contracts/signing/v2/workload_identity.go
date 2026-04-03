package signingv2

func CanonicalWorkloadIdentityBindingPayload(payload WorkloadIdentityBindingPayload) ([]byte, error) {
	descriptor := map[string]any{
		"module_path":   payload.Claims.Descriptor.ModulePath,
		"workload_type": payload.Claims.Descriptor.WorkloadType,
	}
	if payload.Claims.Descriptor.ServiceName != "" {
		descriptor["service_name"] = payload.Claims.Descriptor.ServiceName
	}
	if payload.Claims.Descriptor.TargetPlatform != "" {
		descriptor["target_platform"] = payload.Claims.Descriptor.TargetPlatform
	}
	if payload.Claims.Descriptor.Description != "" {
		descriptor["description"] = payload.Claims.Descriptor.Description
	}
	if payload.Claims.Descriptor.WorkloadIdentityID != "" {
		descriptor["workload_identity_id"] = payload.Claims.Descriptor.WorkloadIdentityID
	}

	return canonicalJSON(map[string]any{
		"claims": map[string]any{
			"descriptor": descriptor,
			"policy": map[string]any{
				"version": payload.Claims.Policy.Version,
			},
		},
		"kind": KindWorkloadIdentityBinding,
		"subject": map[string]any{
			"artifact_class":         payload.Subject.ArtifactClass,
			"artifact_digest":        payload.Subject.ArtifactDigest,
			"derivation_spec_digest": payload.Subject.DerivationSpecDigest,
			"output_id":              payload.Subject.OutputID,
		},
	})
}
