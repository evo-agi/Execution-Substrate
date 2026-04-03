package signingv1

import "encoding/json"

func CanonicalWorkloadIdentityBindingBytes(claims WorkloadIdentityBindingClaims) []byte {
	payload := struct {
		ArtifactClass        string `json:"artifact_class"`
		ArtifactDigest       string `json:"artifact_digest"`
		DerivationSpecDigest string `json:"derivation_spec_digest"`
		Description          string `json:"description,omitempty"`
		ModulePath           string `json:"module_path"`
		OutputID             string `json:"output_id"`
		PolicyVersion        string `json:"policy_version"`
		ServiceName          string `json:"service_name,omitempty"`
		TargetPlatform       string `json:"target_platform,omitempty"`
		WorkloadIdentityID   string `json:"workload_identity_id,omitempty"`
		WorkloadType         string `json:"workload_type"`
	}{
		ArtifactClass:        claims.Subject.ArtifactClass,
		ArtifactDigest:       claims.Subject.ArtifactDigest,
		DerivationSpecDigest: claims.Subject.DerivationSpecDigest,
		Description:          claims.Descriptor.Description,
		ModulePath:           claims.Descriptor.ModulePath,
		OutputID:             claims.Subject.OutputID,
		PolicyVersion:        claims.Subject.PolicyVersion,
		ServiceName:          claims.Descriptor.ServiceName,
		TargetPlatform:       claims.Descriptor.TargetPlatform,
		WorkloadIdentityID:   claims.Descriptor.WorkloadIdentityID,
		WorkloadType:         claims.Descriptor.WorkloadType,
	}
	encoded, _ := json.Marshal(payload)
	return encoded
}
