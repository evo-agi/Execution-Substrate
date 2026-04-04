package evidencev1

import (
	"encoding/json"
	"fmt"
	"strings"
)

type PackageClaims struct {
	Identity    ArtifactIdentity `json:"identity"`
	Publication Publication      `json:"publication"`
}

type ArtifactIdentity struct {
	ArtifactDigest string `json:"artifact_digest"`
	PayloadDigest  string `json:"payload_digest"`
	ArtifactType   string `json:"artifact_type"`
	IntentDigest   string `json:"intent_digest"`
}

type Publication struct {
	BuilderService  string           `json:"builder_service"`
	Invoker         Invoker          `json:"invoker"`
	PolicyDecisions []PolicyDecision `json:"policy_decisions"`
	BuildLogDigest  string           `json:"build_log_digest"`
}

type Invoker struct {
	Service   string `json:"service"`
	Principal string `json:"principal"`
}

type PolicyDecision struct {
	Rule   string `json:"rule"`
	Result string `json:"result"`
}

type canonicalPackageClaims struct {
	Identity    canonicalArtifactIdentity `json:"identity"`
	Publication canonicalPublication      `json:"publication"`
}

type canonicalArtifactIdentity struct {
	ArtifactDigest string `json:"artifact_digest"`
	PayloadDigest  string `json:"payload_digest"`
	ArtifactType   string `json:"artifact_type"`
	IntentDigest   string `json:"intent_digest"`
}

type canonicalInvoker struct {
	Service   string `json:"service"`
	Principal string `json:"principal"`
}

type canonicalDecision struct {
	Rule   string `json:"rule"`
	Result string `json:"result"`
}

type canonicalPublication struct {
	BuilderService  string              `json:"builder_service"`
	Invoker         canonicalInvoker    `json:"invoker"`
	PolicyDecisions []canonicalDecision `json:"policy_decisions"`
	BuildLogDigest  string              `json:"build_log_digest"`
}

func NewArtifactIdentity(payloadDigest string, artifactType string, intentDigest string) (ArtifactIdentity, error) {
	artifactDigest, err := DeriveArtifactDigest(payloadDigest, artifactType, intentDigest)
	if err != nil {
		return ArtifactIdentity{}, err
	}
	return ArtifactIdentity{
		ArtifactDigest: artifactDigest,
		PayloadDigest:  strings.TrimSpace(payloadDigest),
		ArtifactType:   strings.TrimSpace(artifactType),
		IntentDigest:   strings.TrimSpace(intentDigest),
	}, nil
}

func DeriveArtifactDigest(payloadDigest string, artifactType string, intentDigest string) (string, error) {
	trimmedPayloadDigest := strings.TrimSpace(payloadDigest)
	trimmedArtifactType := strings.TrimSpace(artifactType)
	trimmedIntentDigest := strings.TrimSpace(intentDigest)

	if err := validateDigest(trimmedPayloadDigest); err != nil {
		return "", fmt.Errorf("package identity payload_digest: %w", err)
	}
	if trimmedArtifactType == "" {
		return "", fmt.Errorf("package identity artifact_type is required")
	}
	if err := validateDigest(trimmedIntentDigest); err != nil {
		return "", fmt.Errorf("package identity intent_digest: %w", err)
	}

	type packageIdentityProjection struct {
		SchemaVersion string `json:"schema_version"`
		PayloadDigest string `json:"payload_digest"`
		ArtifactType  string `json:"artifact_type"`
		IntentDigest  string `json:"intent_digest"`
	}

	canonical, err := json.Marshal(packageIdentityProjection{
		SchemaVersion: Version,
		PayloadDigest: trimmedPayloadDigest,
		ArtifactType:  trimmedArtifactType,
		IntentDigest:  trimmedIntentDigest,
	})
	if err != nil {
		return "", err
	}
	return ContentDigest(canonical), nil
}

func (p PackageClaims) validate() error {
	requiredDigests := map[string]string{
		"claims.package.identity.artifact_digest":     p.Identity.ArtifactDigest,
		"claims.package.identity.payload_digest":      p.Identity.PayloadDigest,
		"claims.package.identity.intent_digest":       p.Identity.IntentDigest,
		"claims.package.publication.build_log_digest": p.Publication.BuildLogDigest,
	}
	for field, digest := range requiredDigests {
		if err := validateDigest(strings.TrimSpace(digest)); err != nil {
			return fmt.Errorf("%s: %w", field, err)
		}
	}

	derivedArtifactDigest, err := DeriveArtifactDigest(p.Identity.PayloadDigest, p.Identity.ArtifactType, p.Identity.IntentDigest)
	if err != nil {
		return err
	}
	if strings.TrimSpace(p.Identity.ArtifactDigest) != derivedArtifactDigest {
		return fmt.Errorf("claims.package.identity.artifact_digest must match the derived package identity digest")
	}

	requiredStrings := map[string]string{
		"claims.package.identity.artifact_type":        p.Identity.ArtifactType,
		"claims.package.publication.builder_service":   p.Publication.BuilderService,
		"claims.package.publication.invoker.service":   p.Publication.Invoker.Service,
		"claims.package.publication.invoker.principal": p.Publication.Invoker.Principal,
	}
	for field, value := range requiredStrings {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", field)
		}
	}

	return nil
}

func (p PackageClaims) canonicalize() canonicalPackageClaims {
	decisions := normalizePolicyDecisions(p.Publication.PolicyDecisions)
	canonicalDecisions := make([]canonicalDecision, 0, len(decisions))
	for _, decision := range decisions {
		canonicalDecisions = append(canonicalDecisions, canonicalDecision{
			Rule:   strings.TrimSpace(decision.Rule),
			Result: strings.TrimSpace(decision.Result),
		})
	}

	return canonicalPackageClaims{
		Identity: canonicalArtifactIdentity{
			ArtifactDigest: strings.TrimSpace(p.Identity.ArtifactDigest),
			PayloadDigest:  strings.TrimSpace(p.Identity.PayloadDigest),
			ArtifactType:   strings.TrimSpace(p.Identity.ArtifactType),
			IntentDigest:   strings.TrimSpace(p.Identity.IntentDigest),
		},
		Publication: canonicalPublication{
			BuilderService: strings.TrimSpace(p.Publication.BuilderService),
			Invoker: canonicalInvoker{
				Service:   strings.TrimSpace(p.Publication.Invoker.Service),
				Principal: strings.TrimSpace(p.Publication.Invoker.Principal),
			},
			PolicyDecisions: canonicalDecisions,
			BuildLogDigest:  strings.TrimSpace(p.Publication.BuildLogDigest),
		},
	}
}
