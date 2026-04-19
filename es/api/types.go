package api

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
	ArtifactRegistry string `json:"artifact_registry"`
}

type HealthReadiness struct {
	ServerStarted string `json:"server_started"`
	TrustModel    string `json:"trust_model"`
}
