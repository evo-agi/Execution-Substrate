package admission

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"execution-substrate/es/admission/internal/admissionstate"
	"execution-substrate/es/admission/internal/reliablesubmit"
	evidencev1 "execution-substrate/internal/contracts/evidence/v1"
)

// The evidence cap is the store's: custody and admission refuse the same size.
const maxOperationalEvidenceBytes = reliablesubmit.OperationalEvidenceLimit

var errOperationalAdmissionCommission = errors.New("private operational admission unavailable")

// The view, the withdrawal and supersession latches and the confirmation time
// live in the package admissionstate. This package holds only the handle
// Service.operational and reaches the state through its methods.

// Nil in production. Tests may count calls made by the selected built-in set.
// skew adds elapsed time to the confirmation deadline; it cannot remove any.
// stricter is evaluated after the selected built-in set of the view; the set
// stops at the first refusal, so it can refuse a claim or require an input,
// and it cannot allow what the built-in set refuses.
type operationalAdmissionProofHooks struct {
	required        func([]AdmissionPolicyInputClass)
	evaluated       func(bool)
	contextObserved func(AdmissionPolicyContext)
	skew            func() time.Duration
	stricter        AdmissionPolicyEvaluator
}

// operationalProofOf returns the proof hooks a view was installed with.
func operationalProofOf(view admissionstate.View) *operationalAdmissionProofHooks {
	hooks, _ := view.Proof().(*operationalAdmissionProofHooks)
	return hooks
}

func copyOperationalPolicySet(s admissionPolicySet) (admissionPolicySet, bool) {
	if len(s.policies) < 1 || len(s.policies) > 2 {
		return admissionPolicySet{}, false
	}
	out := admissionPolicySet{policies: make([]AdmissionPolicyEvaluator, 0, len(s.policies))}
	for i, candidate := range s.policies {
		switch policy := candidate.(type) {
		case selectedDestructiveShellCommandPolicy:
			if i != 0 {
				return admissionPolicySet{}, false
			}
			out.policies = append(out.policies, policy)
		case configuredStaticScriptLiteralDenyPolicy:
			if i != 1 || len(policy.entries) == 0 {
				return admissionPolicySet{}, false
			}
			cloned := configuredStaticScriptLiteralDenyPolicy{entries: slices.Clone(policy.entries)}
			out.policies = append(out.policies, cloned)
		default:
			// Do not invoke an unsupported or nested evaluator to discover it.
			return admissionPolicySet{}, false
		}
	}
	if _, ok := out.policies[0].(selectedDestructiveShellCommandPolicy); !ok {
		return admissionPolicySet{}, false
	}
	return out, true
}

func operationalPolicyEquals(a, b admissionPolicySet) bool {
	if len(a.policies) != len(b.policies) {
		return false
	}
	for i := range a.policies {
		switch actual := a.policies[i].(type) {
		case selectedDestructiveShellCommandPolicy:
			if _, ok := b.policies[i].(selectedDestructiveShellCommandPolicy); !ok {
				return false
			}
		case configuredStaticScriptLiteralDenyPolicy:
			want, ok := b.policies[i].(configuredStaticScriptLiteralDenyPolicy)
			if !ok || !slices.Equal(actual.entries, want.entries) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// operationalPolicyContent names a copied built-in set as plain content: the
// id of each selected policy and every configured entry, in order.
func operationalPolicyContent(set admissionPolicySet) ([]admissionstate.Policy, bool) {
	out := make([]admissionstate.Policy, 0, len(set.policies))
	for _, candidate := range set.policies {
		switch policy := candidate.(type) {
		case selectedDestructiveShellCommandPolicy:
			out = append(out, admissionstate.Policy{ID: string(selectedDestructiveShellCommandPolicyID)})
		case configuredStaticScriptLiteralDenyPolicy:
			entries := make([]admissionstate.PolicyEntry, 0, len(policy.entries))
			for _, entry := range policy.entries {
				entries = append(entries, admissionstate.PolicyEntry{ID: entry.id, Literal: entry.literal})
			}
			out = append(out, admissionstate.Policy{ID: string(configuredStaticScriptLiteralDenyPolicyID), Entries: entries})
		default:
			return nil, false
		}
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

// operationalPolicySet builds the built-in set that plain content names. It
// accepts exactly the shapes operationalPolicyContent produces from a copied
// set: the selected policy first and without entries, then at most the
// configured policy with at least one entry.
func operationalPolicySet(policies []admissionstate.Policy) (admissionPolicySet, bool) {
	if len(policies) < 1 || len(policies) > 2 {
		return admissionPolicySet{}, false
	}
	out := admissionPolicySet{policies: make([]AdmissionPolicyEvaluator, 0, len(policies))}
	for i, policy := range policies {
		switch AdmissionPolicyID(policy.ID) {
		case selectedDestructiveShellCommandPolicyID:
			if i != 0 || len(policy.Entries) != 0 {
				return admissionPolicySet{}, false
			}
			out.policies = append(out.policies, selectedDestructiveShellCommandPolicy{})
		case configuredStaticScriptLiteralDenyPolicyID:
			if i != 1 || len(policy.Entries) == 0 {
				return admissionPolicySet{}, false
			}
			entries := make([]configuredStaticScriptLiteralDenyEntry, 0, len(policy.Entries))
			for _, entry := range policy.Entries {
				entries = append(entries, configuredStaticScriptLiteralDenyEntry{id: entry.ID, literal: entry.Literal})
			}
			out.policies = append(out.policies, configuredStaticScriptLiteralDenyPolicy{entries: entries})
		default:
			return admissionPolicySet{}, false
		}
	}
	return out, true
}

// operationalAdmissionContent copies what this Service would enforce and
// names it. The caller holds Service.mu.
func (s *Service) operationalAdmissionContent() (content admissionstate.Content, digest [32]byte, ok bool) {
	if !s.trustModelVerified || s.trustModelOwner != s || s.trustModel == nil || s.provenanceVerifier == nil ||
		s.trustModel.Validate() != nil {
		return admissionstate.Content{}, [32]byte{}, false
	}
	trustBytes, err := json.Marshal(s.trustModel)
	if err != nil || int64(len(trustBytes)) > maxDependencyJSONResponseBytes {
		return admissionstate.Content{}, [32]byte{}, false
	}
	configured := s.provenanceVerifier
	if configured.algorithm != "ed25519" || strings.TrimSpace(configured.keyID) == "" ||
		len(configured.publicKey) != ed25519.PublicKeySize {
		return admissionstate.Content{}, [32]byte{}, false
	}
	if cfg := s.cfg.AdmissionPolicy; cfg != nil && cfg.Validate() != nil {
		return admissionstate.Content{}, [32]byte{}, false
	}
	expected, typeOK := admissionPolicyEvaluatorFromConfig(s.cfg.AdmissionPolicy).(admissionPolicySet)
	if !typeOK {
		return admissionstate.Content{}, [32]byte{}, false
	}
	var selected admissionPolicySet
	if s.admissionPolicyEvaluator == nil {
		selected, ok = copyOperationalPolicySet(expected)
	} else {
		actual, isSet := s.admissionPolicyEvaluator.(admissionPolicySet)
		if !isSet {
			return admissionstate.Content{}, [32]byte{}, false
		}
		selected, ok = copyOperationalPolicySet(actual)
		if ok && !operationalPolicyEquals(selected, expected) {
			ok = false
		}
	}
	if !ok {
		return admissionstate.Content{}, [32]byte{}, false
	}
	policies, ok := operationalPolicyContent(selected)
	if !ok {
		return admissionstate.Content{}, [32]byte{}, false
	}
	// The view enforces the normalized lists, and the digest is taken over
	// exactly these values. Normalized returns newly allocated lists, and the
	// state copies the content again when it installs it, so the view shares
	// no backing array with the Service's own trust model.
	content = admissionstate.Content{
		Trust: s.trustModel.Normalized(),
		Verifier: admissionstate.Verifier{
			Algorithm: configured.algorithm,
			KeyID:     configured.keyID,
			PublicKey: append([]byte(nil), configured.publicKey...),
		},
		Policies: policies,
	}
	digest, ok = admissionstate.Digest(content)
	if !ok {
		return admissionstate.Content{}, [32]byte{}, false
	}
	return content, digest, true
}

// installOperationalAdmission is the one place a view is created. The store
// write runs without Service.mu, and the view is installed only after that
// transaction has ended, with the token the store returned for exactly the
// content this Service copied. The state refuses a token that does not name
// this realm and this content, and a second view. Service.mu is held across
// the install, before the state's own lock, so a trust load cannot run
// between the comparison of the trust model and the install. It must not be
// called inside a writer turn.
func (s *Service) installOperationalAdmission(ctx context.Context, d *operationalDomain,
	write func(digest [32]byte) (reliablesubmit.OperationalAdmissionToken, error)) error {
	if s == nil || d == nil || d.self != d || d.custody == nil || write == nil ||
		d.realm.installation == [32]byte{} || d.realm.epoch == 0 || ctx.Err() != nil {
		return errOperationalAdmissionCommission
	}
	s.mu.RLock()
	sampled := s.trustModel
	installable := s.operational.Installable(s)
	content, digest, ok := s.operationalAdmissionContent()
	s.mu.RUnlock()
	if !installable || !ok {
		return errOperationalAdmissionCommission
	}
	token, err := write(digest)
	if err != nil || !token.Names(d.realm.installation, d.realm.epoch, digest) {
		return errOperationalAdmissionCommission
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// A trust load that raced the store write leaves the row in place and this
	// Service without a view: it stays closed.
	if s.trustModel != sampled || s.trustModelOwner != s || !s.trustModelVerified {
		return errOperationalAdmissionCommission
	}
	hooks := s.operationalProof
	var skew func() time.Duration
	if hooks != nil {
		skew = func() time.Duration {
			if hooks.skew == nil {
				return 0
			}
			return hooks.skew()
		}
	}
	if !s.operational.Install(s, d.realm.installation, d.realm.epoch, token, content, hooks, skew) {
		return errOperationalAdmissionCommission
	}
	return nil
}

// commissionOperationalAdmission is private and has no production caller. It
// creates generation 1 on an empty domain, or joins the stored generation
// when the domain already holds exactly this Service's content.
func (s *Service) commissionOperationalAdmission(ctx context.Context, d *operationalDomain) error {
	return s.installOperationalAdmission(ctx, d, func(digest [32]byte) (reliablesubmit.OperationalAdmissionToken, error) {
		return d.custody.CommissionOperationalAdmission(ctx, d.realm.installation, d.realm.epoch, digest)
	})
}

// advanceOperationalAdmission is private and has no production caller. A
// fresh Service whose content differs from the stored row replaces it at the
// next generation; every process holding the old token is fenced at its next
// first-effect write. A Service that already holds a view cannot advance.
func (s *Service) advanceOperationalAdmission(ctx context.Context, d *operationalDomain, expectedGeneration uint64) error {
	return s.installOperationalAdmission(ctx, d, func(digest [32]byte) (reliablesubmit.OperationalAdmissionToken, error) {
		return d.custody.AdvanceOperationalAdmission(ctx, d.realm.installation, d.realm.epoch, digest, expectedGeneration)
	})
}

// withdrawOperationalEffects is private and has no production caller. It
// stops this process first and the domain second, and reports true only when
// the durable withdrawal is confirmed. After a false result this process
// stays stopped and the call may be repeated. No lock is held across the
// store write, and it must not be called inside a writer turn.
func (s *Service) withdrawOperationalEffects(ctx context.Context, d *operationalDomain) bool {
	if s == nil || d == nil || d.self != d || d.custody == nil {
		return false
	}
	token, ok := s.operational.Withdraw(s, d.realm.installation, d.realm.epoch)
	if !ok {
		return false
	}
	return d.custody.WithdrawOperationalAdmission(ctx, token) == nil
}

// confirmOperationalAdmission asks EGS for the signed trust model and
// compares it, through the admission digest, with the content this process
// holds. Equal content records the time sampled before the request was sent.
// Different content latches supersession for the life of the process. A
// failed request changes nothing, so the deadline keeps running. It performs
// network I/O and is called outside every writer turn, Service.mu, the lock
// of the admission state and the owner mutex. At the two pre-checks the
// caller holds the custody read lock of the borrow across it.
func (s *Service) confirmOperationalAdmission(ctx context.Context) {
	if s == nil {
		return
	}
	view, ok := s.operational.Confirmable(s)
	// A Service that cannot ask EGS cannot confirm; its deadline keeps running.
	if !ok || s.egsClient == nil || s.egsClient.client == nil || s.trustModelVerifier == nil {
		return
	}
	started := time.Now()
	trust, err := s.fetchVerifiedTrustModel(ctx)
	if err != nil {
		return
	}
	s.operational.Confirm(s, view, trust, started)
}

// currentOperationalAdmission returns the view only while it may be used: it
// exists for this realm, is neither withdrawn nor superseded, and its last
// confirmation is within the limit. Every sample point inherits all of it.
// The admission state decides all of that under its own lock.
func (s *Service) currentOperationalAdmission(realm operationalRealm) (admissionstate.View, bool) {
	if s == nil {
		return admissionstate.View{}, false
	}
	return s.operational.Current(s, realm.installation, realm.epoch)
}

func decodeOperationalEvidence(record string) (evidencev1.ArtifactEvidence, error) {
	var evidence evidencev1.ArtifactEvidence
	if len(record) == 0 || len(record) > maxOperationalEvidenceBytes || !utf8.ValidString(record) {
		return evidence, errPrivateReplayUnavailable
	}
	decoder := json.NewDecoder(strings.NewReader(record))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&evidence); err != nil {
		return evidencev1.ArtifactEvidence{}, errPrivateReplayUnavailable
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return evidencev1.ArtifactEvidence{}, errPrivateReplayUnavailable
	}
	encoded, err := json.Marshal(evidence)
	if err != nil || !bytes.Equal(encoded, []byte(record)) || evidence.Validate() != nil {
		return evidencev1.ArtifactEvidence{}, errPrivateReplayUnavailable
	}
	return evidence, nil
}

func operationalRequestFromIntent(intent privateReplayOriginalIntent) PrepareRequest {
	request := PrepareRequest{SchemaVersion: "v1", Mode: ExecutionMode(intent.mode.value),
		TimeoutSeconds: int(intent.timeout.value), Invocation: ArtifactInvocation{
			SchemaVersion:  intent.invocationSchema.value,
			ArtifactDigest: intent.artifactDigest, DerivationSpecDigest: intent.derivationDigest,
			OutputID: intent.outputID, Argv: slices.Clone(intent.argv.value),
			Env: copyStringMap(intent.env.value), Annotations: copyStringMap(intent.annotations.value),
		}}
	if intent.resources.present {
		resources := intent.resources.value
		request.Resources = &resources
	}
	return request
}

func operationalEvidenceMatchesOriginal(evidence evidencev1.ArtifactEvidence, original verifiedOperationalOriginal,
	realm operationalRealm) bool {
	delivery, resolved := original.delivery, original.resolved
	plan := resolved.plan
	identity := evidence.Claims.Package.Identity
	claims := evidence.Claims.Admission
	if identity.ArtifactDigest != plan.artifactDigest ||
		identity.ArtifactDigest != delivery.originalIntent.artifactDigest ||
		identity.PayloadDigest != plan.payloadDigest ||
		identity.PayloadDigest != digestBytes(resolved.material.payloadBytes) ||
		claims.Authorization.Derivation.DerivationSpecDigest != plan.derivationSpecDigest ||
		claims.Authorization.Derivation.OutputID != plan.outputID ||
		identity.ArtifactType != "static-script" ||
		len(claims.Execution.Runtime.RequiredCapabilities) != 0 ||
		claims.Execution.Access.NetworkAccess || plan.networkAccess ||
		(claims.Execution.Workload.TargetPlatform != "" && claims.Execution.Workload.TargetPlatform != "docker") ||
		requestedRuntimeProfileName(delivery.request) != plan.runtimeProfile.name ||
		!validateOperationalPlan(delivery, resolved, realm) {
		return false
	}
	return validateInvocationAgainstManifest(delivery.request.Invocation, manifestFromEvidence(evidence)) == nil
}

func completeOperationalPolicyInputs(policyCtx *AdmissionPolicyContext, required []AdmissionPolicyInputClass, payload []byte) bool {
	for _, input := range required {
		switch input {
		case AdmissionPolicyInputInvocationArgv, AdmissionPolicyInputArtifactEvidenceMetadata,
			AdmissionPolicyInputRuntimeProfileMetadata:
		case AdmissionPolicyInputPayloadDigestAndByteCount, AdmissionPolicyInputStaticScriptPayloadText:
			if len(payload) == 0 || len(payload) > maxAdmissionPolicyPayloadBytes {
				return false
			}
			policyCtx.PayloadByteCount = int64(len(payload))
		default:
			return false
		}
	}
	if admissionPolicyRequiresStaticScriptText(required) {
		text, failure := staticScriptPayloadTextForAdmissionPolicy(payload)
		if failure != nil {
			return false
		}
		policyCtx.StaticScriptPayloadText = text
		policyCtx.StaticScriptPayloadTextPresent = true
	}
	return true
}

// qualifyOperationalRetained judges a retained original under this process's
// own current view. A refusal by the current content is Denied; an absent,
// withdrawn, superseded or unconfirmed view and an input the built-in set
// cannot evaluate are Unavailable; evidence that contradicts the
// authenticated original is Integrity.
func (s *Service) qualifyOperationalRetained(ctx context.Context, original verifiedOperationalOriginal,
	realm operationalRealm) reliablesubmit.OperationalReason {
	if ctx.Err() != nil {
		return reliablesubmit.OperationalCanceled
	}
	view, ok := s.currentOperationalAdmission(realm)
	if !ok {
		return reliablesubmit.OperationalUnavailable
	}
	evidence, err := decodeOperationalEvidence(original.resolved.provenanceRecord)
	if err != nil {
		return reliablesubmit.OperationalIntegrity
	}
	if !operationalEvidenceMatchesOriginal(evidence, original, realm) {
		return reliablesubmit.OperationalIntegrity
	}
	verifier := view.Verifier()
	if evidencev1.Verify(evidence, verifier.KeyID, verifier.Algorithm, verifier.PublicKey) != nil {
		return reliablesubmit.OperationalDenied
	}
	if enforceTrustModel(view.Trust(), evidence.Seal.KeyID,
		evidence.Claims.Package.Identity.ArtifactDigest) != nil {
		return reliablesubmit.OperationalDenied
	}
	// The built-in set is built from the content the view holds, which is the
	// content its digest names. A shape the content cannot have refuses.
	policy, ok := operationalPolicySet(view.Policies())
	if !ok {
		return reliablesubmit.OperationalUnavailable
	}
	proof := operationalProofOf(view)
	if proof != nil && proof.stricter != nil {
		policy.policies = append(policy.policies, proof.stricter)
	}
	artifact := preparedArtifact{
		manifest:       manifestFromEvidence(evidence),
		payloadDigest:  evidence.Claims.Package.Identity.PayloadDigest,
		targetPlatform: evidence.Claims.Admission.Execution.Workload.TargetPlatform,
		networkAccess:  evidence.Claims.Admission.Execution.Access.NetworkAccess,
	}
	policyCtx := newAdmissionPolicyContext(original.delivery.request, artifact)
	required := policy.RequiredInputClasses(policyCtx)
	if proof != nil && proof.required != nil {
		proof.required(slices.Clone(required))
	}
	if !completeOperationalPolicyInputs(&policyCtx, required, original.resolved.material.payloadBytes) {
		return reliablesubmit.OperationalUnavailable
	}
	if proof != nil && proof.contextObserved != nil {
		observed := policyCtx
		observed.InvocationArgv = slices.Clone(policyCtx.InvocationArgv)
		proof.contextObserved(observed)
	}
	decision := policy.Evaluate(ctx, policyCtx)
	if proof != nil && proof.evaluated != nil {
		proof.evaluated(decision.Allow)
	}
	if !decision.Allow {
		return reliablesubmit.OperationalDenied
	}
	if ctx.Err() != nil {
		return reliablesubmit.OperationalCanceled
	}
	// Withdrawal, supersession or the deadline can arrive during bounded
	// local evaluation.
	if current, still := s.currentOperationalAdmission(realm); !still || current != view {
		return reliablesubmit.OperationalUnavailable
	}
	return reliablesubmit.OperationalReasonNone
}
