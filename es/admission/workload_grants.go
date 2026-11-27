package admission

import (
	"context"
	"net/http"
	"strings"

	"execution-substrate/es/admission/internal/grantcaller"
	esconfig "execution-substrate/es/config"
	"execution-substrate/internal/callerauth"
	evidencev1 "execution-substrate/internal/contracts/evidence/v1"
)

// Workload grants are the owner's grants in ES deployment configuration
// (admission_policy.workload_grants). A run that requests the network also
// needs a grant that names its publisher, its caller and an egress lane: the
// signed network request is the publisher's request, never the authority.
// The contract is .docs/execution_lifecycle/contracts.md, section 5B.
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
// publisher's signed network request. caller is a grantcaller.Caller, a type
// only package grantcaller can fill in: the caller the ES API authenticated,
// a private delivery's bound caller, or no caller. runtimeProfile is the
// effective runtime profile the runtime-profile gate resolved.
type workloadGrantFacts struct {
	evidence       workloadGrantEvidenceFacts
	caller         grantcaller.Caller
	artifactType   string
	runtimeProfile string
	networkAccess  bool
}

// matchKey returns the five match facts in the order of
// esconfig.WorkloadGrantRuleConfig.MatchKey.
func (f workloadGrantFacts) matchKey() [5]string {
	return [5]string{f.evidence.publisherPrincipal, f.caller.Principal(), f.evidence.signerKeyID, f.artifactType, f.runtimeProfile}
}

type workloadGrantRule struct {
	id         string
	match      [5]string
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
// byte on all five facts; startup guarantees that at most one rule matches.
// Startup refuses a rule with an empty caller, so a delivery without an
// authenticated caller matches no rule.
func (g workloadGrants) decide(facts workloadGrantFacts) (workloadGrantDecision, *Error) {
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
// artifact, its caller and the runtime profile the runtime-profile gate
// resolved.
func newWorkloadGrantFacts(caller grantcaller.Caller, runtimeProfile string, artifact preparedArtifact) workloadGrantFacts {
	return workloadGrantFacts{
		evidence:       artifact.grantFacts,
		caller:         caller,
		artifactType:   strings.TrimSpace(artifact.manifest.ArtifactType),
		runtimeProfile: runtimeProfile,
		networkAccess:  artifact.networkAccess,
	}
}

// WithAuthenticatedCaller returns ctx carrying the caller the ES API
// authenticated over mTLS for this :prepare or :submit. The ES API is its
// only caller: the caller identity comes from the connection, never from the
// request body, the evidence or a header. It takes a callerauth.Caller, not
// a SPIFFE ID or a string, and admission keeps it as a grantcaller.Caller,
// whose fields only package grantcaller can set, so the Go compiler keeps
// any other value out of the grant facts.
//
// A callerauth.Caller comes only from callerauth's two producers,
// CallerFromConnectionState and Authenticator.Authenticate, which read a TLS
// connection state; the ES API passes Authenticate the request it is
// serving, whose connection state Go's TLS server filled in after verifying
// the client's certificate chain. A guard test,
// TestTheGrantCallerCanComeOnlyFromAVerifiedConnection, checks the forms of
// building or editing a connection state that it names.
//
// A zero Caller carries no caller. ES admission reads the caller only to
// match workload grants, and it never becomes ES request or response
// grammar. A context without one matches no grant, so its run gets no
// network.
func WithAuthenticatedCaller(ctx context.Context, caller callerauth.Caller) context.Context {
	return grantcaller.With(ctx, grantcaller.FromConnection(caller))
}

// withDeliveryCaller returns ctx carrying, in place of any caller ctx
// carried, the caller a private reliable submit delivery is bound to: the
// grant caller that newSyntheticCallerFact built from the same URI as the
// delivery's claim refs. Such a delivery matches workload grants on that
// caller, and on no other; a fact whose URI callerauth would not accept
// carries no caller, so its delivery matches no grant.
func withDeliveryCaller(ctx context.Context, fact syntheticCallerFact) context.Context {
	return grantcaller.With(ctx, fact.grant)
}

// AuthenticatedCallerPrincipal returns the canonical SPIFFE ID of the caller
// that workload grants match on in ctx, or empty when ctx carries none. It
// only reads: the ES API's tests use it to check which caller each handler
// hands admission.
func AuthenticatedCallerPrincipal(ctx context.Context) string {
	return grantcaller.From(ctx).Principal()
}

// decideWorkloadGrants runs in the shared :prepare and :submit admission
// path, after evidence verification and the workload-zone Vault config read,
// and before the content policies, so a refused run fetches no payload for
// policy inspection.
//
// The effective runtime profile comes from the runtime-profile gate itself,
// resolveExecutionRuntimeProfile, so the grant code keeps no list of profile
// names: every profile the gate resolves gets a grant decision. When the gate
// refuses the request (an unknown or disabled profile, or one the artifact
// does not fit), its own 400 unsupported_runtime_profile is the answer, and
// it is returned here, before the content policies. So every run leaves
// admission with a grant decision or a refusal, and a request that names a
// profile ES refuses reads no payload, whoever the caller is (red-team 2,
// RT73B-2). Prepare and submit run the same gate again later with the same
// inputs.
func (s *Service) decideWorkloadGrants(ctx context.Context, req PrepareRequest, artifact preparedArtifact) (workloadGrantDecision, *Error) {
	profile, profileErr := resolveExecutionRuntimeProfile(s.cfg.Execution, req, artifact)
	if profileErr != nil {
		return workloadGrantDecision{}, profileErr
	}
	facts := newWorkloadGrantFacts(grantcaller.From(ctx), profile.name, artifact)
	return workloadGrantsFromConfig(s.cfg.AdmissionPolicy).decide(facts)
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
