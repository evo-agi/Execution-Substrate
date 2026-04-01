package api

import "execution-platform/egs/model"

type SignedTrustModelResponse struct {
	TrustModel    model.TrustModel `json:"trust_model"`
	Algorithm     string           `json:"algorithm"`
	KeyID         string           `json:"key_id"`
	PayloadDigest string           `json:"payload_digest"`
	Signature     string           `json:"signature"`
	// SourceDigest is advisory metadata only in EGS v1. It is not part of the
	// signed payload and must not be used by ES or other consumers for trust
	// decisions. payload_digest and signature are the authoritative trust
	// signals in v1.
	SourceDigest  *string          `json:"source_digest,omitempty"`
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
	Signer       string `json:"signer"`
	TrustModel   string `json:"trust_model"`
	SourceDigest string `json:"source_digest"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}
