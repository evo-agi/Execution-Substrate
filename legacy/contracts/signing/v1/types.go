package signingv1

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

type PolicyDecisionEntry struct {
	Rule   string
	Result string
}

type ProvenanceClaims struct {
	ArtifactDigest   string
	BuilderService   string
	InvokerService   string
	InvokerPrincipal string
	PolicyDecisions  []PolicyDecisionEntry
	BuildLogDigest   string
}

type DerivationConstraintsClaims struct {
	AllowedToolchains      []string `json:"allowed_toolchains"`
	ForbiddenToolchains    []string `json:"forbidden_toolchains"`
	OS                     string   `json:"os"`
	Arch                   string   `json:"arch"`
	NetworkAccess          bool     `json:"network_access"`
	WritablePaths          []string `json:"writable_paths"`
	ForbiddenPaths         []string `json:"forbidden_paths"`
	DeterminismExpectation string   `json:"determinism_expectation"`
}

type DerivationSubjectClaims struct {
	ArtifactDigest       string
	DerivationSpecDigest string
	OutputID             string
}

type DerivationPolicyClaims struct {
	Version              string
	ExpectedArtifactType string
}

type DerivationAttestationClaims struct {
	Subject     DerivationSubjectClaims
	Constraints DerivationConstraintsClaims
	Policy      DerivationPolicyClaims
}

type WorkloadIdentitySubjectClaims struct {
	ArtifactClass        string
	ArtifactDigest       string
	DerivationSpecDigest string
	OutputID             string
	PolicyVersion        string
}

type WorkloadDescriptorClaims struct {
	WorkloadType       string
	ModulePath         string
	ServiceName        string
	TargetPlatform     string
	Description        string
	WorkloadIdentityID string
}

type WorkloadIdentityBindingClaims struct {
	Subject    WorkloadIdentitySubjectClaims
	Descriptor WorkloadDescriptorClaims
}

type DetachedEnvelope struct {
	PayloadDigest    string
	CanonicalSpecB64 string
	SignatureValue   string
	KeyID            string
	Algorithm        string
}

type TrustModelClaims struct {
	AllowedSigners   []string
	RevokedSigners   []string
	RevokedArtifacts []string
	UpdateRevision   int
	Version          string
}

func digestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func normalizeStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}

	normalized := make([]string, 0, len(values))
	for _, value := range values {
		normalized = append(normalized, strings.TrimSpace(value))
	}
	return normalized
}
