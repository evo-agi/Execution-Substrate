package signingv2

import "sort"

func CanonicalProvenancePayload(payload ProvenancePayload) ([]byte, error) {
	decisions := normalizePolicyDecisions(payload.Claims.PolicyDecisions)
	encodedDecisions := make([]any, 0, len(decisions))
	for _, decision := range decisions {
		encodedDecisions = append(encodedDecisions, map[string]any{
			"result": decision.Result,
			"rule":   decision.Rule,
		})
	}

	return canonicalJSON(map[string]any{
		"claims": map[string]any{
			"build_log_digest": payload.Claims.BuildLogDigest,
			"builder_service":  payload.Claims.BuilderService,
			"invoker": map[string]any{
				"principal": payload.Claims.Invoker.Principal,
				"service":   payload.Claims.Invoker.Service,
			},
			"policy_decisions": encodedDecisions,
		},
		"kind": KindProvenance,
		"subject": map[string]any{
			"artifact_digest": payload.Subject.ArtifactDigest,
		},
	})
}

func normalizePolicyDecisions(decisions []PolicyDecision) []PolicyDecision {
	normalized := append([]PolicyDecision(nil), decisions...)
	sort.Slice(normalized, func(i, j int) bool {
		if normalized[i].Rule == normalized[j].Rule {
			return normalized[i].Result < normalized[j].Result
		}
		return normalized[i].Rule < normalized[j].Rule
	})
	return normalized
}
