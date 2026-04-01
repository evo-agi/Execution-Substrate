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
