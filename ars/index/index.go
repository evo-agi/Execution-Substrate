package index

import "fmt"

type Kind string

const (
	KindManifest                           Kind = "manifest"
	KindProvenance                         Kind = "provenance"
	KindDerivationMetadata                 Kind = "derivation-metadata"
	KindDerivationAuthorizationAttestation Kind = "derivation-authorization-attestation"
	KindWorkloadIdentityBinding            Kind = "workload-identity-binding"
)

type Entry struct {
	ArtifactDigest                           string `json:"artifact_digest"`
	ManifestDigest                           string `json:"manifest_digest"`
	ProvenanceDigest                         string `json:"provenance_digest"`
	PayloadDigest                            string `json:"payload_digest"`
	DerivationMetadataDigest                 string `json:"derivation_metadata_digest"`
	DerivationAuthorizationAttestationDigest string `json:"derivation_authorization_attestation_digest"`
	WorkloadIdentityBindingDigest            string `json:"workload_identity_binding_digest"`
	CreatedAt                                string `json:"created_at"`
}

type Lookup interface {
	Path() string
	Count() int
	Lookup(artifactDigest string) (Entry, bool, error)
	Register(entry Entry) (bool, error)
}

func ParseKind(value string) (Kind, bool) {
	switch Kind(value) {
	case KindManifest,
		KindProvenance,
		KindDerivationMetadata,
		KindDerivationAuthorizationAttestation,
		KindWorkloadIdentityBinding:
		return Kind(value), true
	default:
		return "", false
	}
}

func (e Entry) DigestFor(kind Kind) string {
	switch kind {
	case KindManifest:
		return e.ManifestDigest
	case KindProvenance:
		return e.ProvenanceDigest
	case KindDerivationMetadata:
		return e.DerivationMetadataDigest
	case KindDerivationAuthorizationAttestation:
		return e.DerivationAuthorizationAttestationDigest
	case KindWorkloadIdentityBinding:
		return e.WorkloadIdentityBindingDigest
	default:
		return ""
	}
}

type ConflictError struct {
	ArtifactDigest string
}

func (e ConflictError) Error() string {
	return fmt.Sprintf("artifact %s already registered with different digests", e.ArtifactDigest)
}
