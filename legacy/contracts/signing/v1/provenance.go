package signingv1

import (
	"encoding/json"
	"sort"
	"strings"
)

func CanonicalProvenanceBytes(claims ProvenanceClaims) []byte {
	decisions := append([]PolicyDecisionEntry(nil), claims.PolicyDecisions...)
	sort.Slice(decisions, func(i, j int) bool {
		if decisions[i].Rule == decisions[j].Rule {
			return decisions[i].Result < decisions[j].Result
		}
		return decisions[i].Rule < decisions[j].Rule
	})

	parts := make([]string, 0, len(decisions))
	for _, decision := range decisions {
		parts = append(parts, decision.Rule+":"+decision.Result)
	}
	policyDecisionHash := digestBytes([]byte(strings.Join(parts, "|")))

	payload := struct {
		ArtifactDigest      string `json:"artifact_digest"`
		BuilderService      string `json:"builder_service"`
		InvokerService      string `json:"invoker_service"`
		InvokerPrincipal    string `json:"invoker_principal"`
		PolicyDecisionsHash string `json:"policy_decisions_hash"`
		BuildLogDigest      string `json:"build_log_digest"`
	}{
		ArtifactDigest:      claims.ArtifactDigest,
		BuilderService:      claims.BuilderService,
		InvokerService:      claims.InvokerService,
		InvokerPrincipal:    claims.InvokerPrincipal,
		PolicyDecisionsHash: policyDecisionHash,
		BuildLogDigest:      claims.BuildLogDigest,
	}
	encoded, _ := json.Marshal(payload)
	return encoded
}
