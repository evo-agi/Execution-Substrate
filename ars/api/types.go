package api

type BlobErrorResponse struct {
	Error  string `json:"error"`
	Digest string `json:"digest"`
}

type ArtifactErrorResponse struct {
	Error          string `json:"error"`
	ArtifactDigest string `json:"artifact_digest"`
	Digest         string `json:"digest,omitempty"`
}

type RegisterArtifactRequest struct {
	ArtifactDigest                           string `json:"artifact_digest"`
	ManifestDigest                           string `json:"manifest_digest"`
	ProvenanceDigest                         string `json:"provenance_digest"`
	PayloadDigest                            string `json:"payload_digest"`
	DerivationMetadataDigest                 string `json:"derivation_metadata_digest"`
	DerivationAuthorizationAttestationDigest string `json:"derivation_authorization_attestation_digest"`
	WorkloadIdentityBindingDigest            string `json:"workload_identity_binding_digest"`
}

type RegisterArtifactResponse struct {
	Registered     bool   `json:"registered"`
	Created        bool   `json:"created"`
	ArtifactDigest string `json:"artifact_digest"`
}

type HealthResponse struct {
	Status               string                     `json:"status"`
	Ready                bool                       `json:"ready"`
	Service              string                     `json:"service"`
	AdditionalProperties HealthAdditionalProperties `json:"additional_properties"`
}

type HealthAdditionalProperties struct {
	Dependencies HealthDependencies `json:"dependencies"`
	Readiness    HealthReadiness    `json:"readiness"`
}

type HealthDependencies struct {
	Storage string `json:"storage"`
	Index   string `json:"index"`
}

type HealthReadiness struct {
	Storage       string `json:"storage"`
	Index         string `json:"index"`
	ServerStarted string `json:"server_started"`
}
