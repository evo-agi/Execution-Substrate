package index

import "fmt"

type Kind string

const (
	KindDiscovery  Kind = "discovery"
	KindDescriptor Kind = "descriptor"
	KindEvidence   Kind = "evidence"
	KindManifest   Kind = "manifest"
)

type Entry struct {
	ArtifactDigest   string `json:"artifact_digest"`
	DiscoveryDigest  string `json:"discovery_digest"`
	DescriptorDigest string `json:"descriptor_digest"`
	CreatedAt        string `json:"created_at"`
}

type Lookup interface {
	Path() string
	Count() int
	Lookup(artifactDigest string) (Entry, bool, error)
	Register(entry Entry) (bool, error)
}

func ParseKind(value string) (Kind, bool) {
	switch Kind(value) {
		case KindDiscovery, KindDescriptor, KindEvidence, KindManifest:
			return Kind(value), true
		default:
			return "", false
	}
}

type ConflictError struct {
	ArtifactDigest string
}

func (e ConflictError) Error() string {
	return fmt.Sprintf("artifact %s already registered with different digests", e.ArtifactDigest)
}
