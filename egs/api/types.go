package api

import "execution-substrate/egs/contract"

type SignedRuntimeTrustResponse struct {
	RuntimeTrust  contract.RuntimeTrustPolicy  `json:"runtime_trust"`
	Algorithm     string                       `json:"algorithm"`
	KeyID         string                       `json:"key_id"`
	PayloadDigest string                       `json:"payload_digest"`
	Signature     string                       `json:"signature"`
	Publication   contract.PublicationMetadata `json:"publication"`
}

type HealthResponse struct {
	Status               string                     `json:"status"`
	Ready                bool                       `json:"ready"`
	Service              string                     `json:"service"`
	AdditionalProperties HealthAdditionalProperties `json:"additional_properties"`
}

type HealthAdditionalProperties struct {
	Readiness HealthReadiness `json:"readiness"`
}

type HealthReadiness struct {
	Signer     string `json:"signer"`
	TrustModel string `json:"trust_model"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}
