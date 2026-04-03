package index

import "fmt"

type Kind string

const (
	KindEvidence Kind = "evidence"
	KindManifest Kind = "manifest"
)

type Entry struct {
	ArtifactDigest string `json:"artifact_digest"`
	EvidenceDigest string `json:"evidence_digest"`
	ManifestDigest string `json:"manifest_digest,omitempty"`
	PayloadDigest  string `json:"payload_digest"`
	CreatedAt      string `json:"created_at"`
}

type Lookup interface {
	Path() string
	Count() int
	Lookup(artifactDigest string) (Entry, bool, error)
	Register(entry Entry) (bool, error)
}

func ParseKind(value string) (Kind, bool) {
	switch Kind(value) {
		case KindEvidence, KindManifest:
			return Kind(value), true
		default:
			return "", false
	}
}

func (e Entry) DigestFor(kind Kind) string {
	switch kind {
		case KindEvidence:
			return e.EvidenceDigest
		case KindManifest:
			return e.ManifestDigest
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
