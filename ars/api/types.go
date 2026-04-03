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

const ArtifactDescriptorSchemaVersion = "v1"

type ArtifactDescriptor struct {
	SchemaVersion string           `json:"schema_version"`
	Artifact      ArtifactIdentity `json:"artifact"`
	Package       ArtifactPackage  `json:"package"`
}

type ArtifactIdentity struct {
	ArtifactDigest string `json:"artifact_digest"`
	ArtifactType   string `json:"artifact_type"`
	IntentDigest   string `json:"intent_digest"`
}

type ArtifactPackage struct {
	Evidence   ArtifactBlobRef      `json:"evidence"`
	Payload    ArtifactBlobRef      `json:"payload"`
	Supporting []ArtifactSupportRef `json:"supporting,omitempty"`
}

type ArtifactBlobRef struct {
	Digest    string `json:"digest"`
	MediaType string `json:"media_type,omitempty"`
}

type ArtifactSupportRef struct {
	Name      string `json:"name"`
	Digest    string `json:"digest"`
	MediaType string `json:"media_type,omitempty"`
}

type RegisterArtifactRequest struct {
	DescriptorDigest string `json:"descriptor_digest"`
}

type RegisterArtifactResponse struct {
	Registered       bool   `json:"registered"`
	Created          bool   `json:"created"`
	ArtifactDigest   string `json:"artifact_digest"`
	DescriptorDigest string `json:"descriptor_digest"`
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
