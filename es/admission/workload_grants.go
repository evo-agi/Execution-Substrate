package admission

import (
	"net/http"
	"strings"

	esconfig "execution-substrate/es/config"
	evidencev1 "execution-substrate/internal/contracts/evidence/v1"
)

// Workload grants are the owner's grants in ES deployment configuration
// (admission_policy.workload_grants). A run that requests the network also
// needs a grant that names an egress lane. The contract is
// .docs/execution_lifecycle/contracts.md, section 5B.
//
// This file decides in grant terms only: a rule ID and an egress lane name.
// It names no scheduler, container runtime or container label; runtime
// realization alone maps a lane to job values. A guard test keeps it so.

const (
	codeNetworkAccessNotGranted    = "network_access_not_granted"
	networkGrantPolicyID           = AdmissionPolicyID("execution-substrate.admission.network-grant/v1")
	networkAccessNotGrantedMessage = "network access not granted by admission policy"
)

// workloadGrantEvidenceFacts are the two grant facts ES reads from verified
// artifact evidence.
type workloadGrantEvidenceFacts struct {
	publisherPrincipal string
	signerKeyID        string
}

// workloadGrantEvidenceFactsFrom reads the grant facts from evidence whose
// seal ES has verified. The publisher principal is the one AGS publication
// claim ES admission reads, and it reads it only to match workload grants:
// it never becomes ES request or response grammar. The signed canonical
// forms of both values are trimmed, so the trimmed values are the ones the
// evidence signature covers. A guard test allows the publication field names
// in this function only.
func workloadGrantEvidenceFactsFrom(evidence evidencev1.ArtifactEvidence) workloadGrantEvidenceFacts {
	return workloadGrantEvidenceFacts{
		publisherPrincipal: strings.TrimSpace(evidence.Claims.Package.Publication.Invoker.Principal),
		signerKeyID:        strings.TrimSpace(evidence.Seal.KeyID),
	}
}

// workloadGrantFacts are the facts a grant rule matches on, plus the
// publisher's signed network request. runtimeProfileSupported is false when
// the request names a runtime profile ES does not support.
type workloadGrantFacts struct {
	evidence                workloadGrantEvidenceFacts
	artifactType            string
	runtimeProfile          string
	runtimeProfileSupported bool
	networkAccess           bool
}

// matchKey returns the four match facts in the order of
// esconfig.WorkloadGrantRuleConfig.MatchKey.
func (f workloadGrantFacts) matchKey() [4]string {
	return [4]string{f.evidence.publisherPrincipal, f.evidence.signerKeyID, f.artifactType, f.runtimeProfile}
}

type workloadGrantRule struct {
	id         string
	match      [4]string
	egressLane string
}

type workloadGrants struct {
	rules []workloadGrantRule
}

// workloadGrantDecision is the outcome for an admitted run. ruleID is empty
// when no rule matched; egressLane is empty when the run gets no network.
type workloadGrantDecision struct {
	ruleID     string
	egressLane string
}

// workloadGrantsFromConfig copies the validated grants. ES startup refuses
// invalid grants (es/config), so the copy needs no checks of its own. A
// configuration without grants yields no rules: only runs that request no
// network are admitted.
func workloadGrantsFromConfig(cfg *esconfig.AdmissionPolicyConfig) workloadGrants {
	if cfg == nil || cfg.WorkloadGrants == nil {
		return workloadGrants{}
	}
	rules := make([]workloadGrantRule, 0, len(cfg.WorkloadGrants.Rules))
	for _, rule := range cfg.WorkloadGrants.Rules {
		rules = append(rules, workloadGrantRule{id: rule.ID, match: rule.MatchKey(), egressLane: rule.EgressLane})
	}
	return workloadGrants{rules: rules}
}

// decide applies the network grant policy,
// execution-substrate.admission.network-grant/v1. Matching is byte for
// byte on all four facts; startup guarantees that at most one rule matches.
func (g workloadGrants) decide(facts workloadGrantFacts) (workloadGrantDecision, *Error) {
	if !facts.runtimeProfileSupported {
		// The runtime-profile gate refuses this request with
		// 400 unsupported_runtime_profile before any effect, and that is the
		// refusal the caller gets: the grant policies do not report on a
		// profile ES does not support.
		return workloadGrantDecision{}, nil
	}
	key := facts.matchKey()
	var matched *workloadGrantRule
	for i := range g.rules {
		if g.rules[i].match == key {
			matched = &g.rules[i]
			break
		}
	}
	var decision workloadGrantDecision
	if matched != nil {
		decision.ruleID = matched.id
	}
	if !facts.networkAccess {
		// A grant never gives a network to a run that did not request one.
		return decision, nil
	}
	if matched == nil || matched.egressLane == "" {
		return workloadGrantDecision{}, networkAccessNotGrantedError()
	}
	decision.egressLane = matched.egressLane
	return decision, nil
}

// newWorkloadGrantFacts reads the grant facts of a run from its verified
// artifact and its request.
func newWorkloadGrantFacts(req PrepareRequest, artifact preparedArtifact) workloadGrantFacts {
	profile, supported := workloadGrantRuntimeProfile(req)
	return workloadGrantFacts{
		evidence:                artifact.grantFacts,
		artifactType:            strings.TrimSpace(artifact.manifest.ArtifactType),
		runtimeProfile:          profile,
		runtimeProfileSupported: supported,
		networkAccess:           artifact.networkAccess,
	}
}

// workloadGrantRuntimeProfile returns the effective runtime profile name of a
// request: static-script/default when the request names none. It reports
// false for a name the runtime-profile gate refuses by name alone, the way
// resolveExecutionRuntimeProfile reads the annotation; a test keeps the two
// in step.
func workloadGrantRuntimeProfile(req PrepareRequest) (string, bool) {
	switch requested := strings.TrimSpace(req.Invocation.Annotations[runtimeProfileAnnotationKey]); requested {
	case "":
		return runtimeProfileDefaultStaticScript, true
	case runtimeProfileControlPlaneNormalShell:
		return requested, true
	default:
		return requested, false
	}
}

// decideWorkloadGrants runs in the shared :prepare and :submit admission
// path, after evidence verification and the workload-zone Vault config read,
// and before the content policies, so a refused run fetches no payload for
// policy inspection.
func (s *Service) decideWorkloadGrants(req PrepareRequest, artifact preparedArtifact) (workloadGrantDecision, *Error) {
	return workloadGrantsFromConfig(s.cfg.AdmissionPolicy).decide(newWorkloadGrantFacts(req, artifact))
}

// networkAccessNotGrantedError is the denial of the network grant policy,
// networkGrantPolicyID, in the redacted error envelope every ES admission
// policy denial uses: status, reason code and safe message only.
func networkAccessNotGrantedError() *Error {
	return &Error{
		Status:  http.StatusForbidden,
		Code:    codeNetworkAccessNotGranted,
		Message: networkAccessNotGrantedMessage,
	}
}
