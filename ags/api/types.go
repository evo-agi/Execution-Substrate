package api

type ErrorResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`
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
	ArtifactRegistry string `json:"artifact_registry"`
}

type HealthReadiness struct {
	ServerStarted string `json:"server_started"`
	Signer        string `json:"signer"`
}
