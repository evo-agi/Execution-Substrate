package admission

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	egsmodel "execution-substrate/egs/model"
	"execution-substrate/es/admission/internal/reliablesubmit"
	evidencev1 "execution-substrate/internal/contracts/evidence/v1"
)

// The evidence cap is the store's: custody and admission refuse the same size.
const maxOperationalEvidenceBytes = reliablesubmit.OperationalEvidenceLimit

// operationalAdmissionConfirmationLimit is how long a view may be used after
// the last confirmation that EGS still serves the commissioned trust.
const operationalAdmissionConfirmationLimit = 30 * time.Second

var errOperationalAdmissionCommission = errors.New("private operational admission unavailable")

// operationalAdmissionSnapshot is the view: an immutable copy of the admission
// content, installed once, together with the token of the admission row it was
// commissioned or advanced under. Its owner link prevents a copy of Service
// from borrowing the authority.
type operationalAdmissionSnapshot struct {
	owner        *Service
	installation [32]byte
	epoch        uint64
	token        reliablesubmit.OperationalAdmissionToken
	trust        egsmodel.RuntimeTrustPolicy
	verifier     ed25519Verifier
	policy       admissionPolicySet
	proof        *operationalAdmissionProofHooks
}

// Nil in production. Tests may count calls made by the selected built-in set.
// skew adds elapsed time to the confirmation deadline; it cannot remove any.
type operationalAdmissionProofHooks struct {
	required        func([]AdmissionPolicyInputClass)
	evaluated       func(bool)
	contextObserved func(AdmissionPolicyContext)
	skew            func() time.Duration
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

// operationalAdmissionDigest names the admission content: the normalized
// trust lists, the evidence verifier, and the selected built-in policies with
// every configured entry. It is taken over the values a view holds, so what
// is hashed is what is enforced. It does not cover the compiled behaviour of
// a built-in policy; two releases with equal configuration present one digest.
func operationalAdmissionDigest(trust egsmodel.RuntimeTrustPolicy, verifier ed25519Verifier, policy admissionPolicySet) ([32]byte, bool) {
	canonical, err := trust.CanonicalBytes()
	if err != nil || len(policy.policies) == 0 {
		return [32]byte{}, false
	}
	b := operationalFrame([]byte("ESOHADM1"), canonical)
	b = operationalFrame(b, []byte(verifier.algorithm))
	b = operationalFrame(b, []byte(verifier.keyID))
	b = operationalFrame(b, verifier.publicKey)
	b = binary.BigEndian.AppendUint32(b, uint32(len(policy.policies)))
	for _, candidate := range policy.policies {
		switch selected := candidate.(type) {
		case selectedDestructiveShellCommandPolicy:
			b = operationalFrame(b, []byte(selectedDestructiveShellCommandPolicyID))
			b = binary.BigEndian.AppendUint32(b, 0)
		case configuredStaticScriptLiteralDenyPolicy:
			b = operationalFrame(b, []byte(configuredStaticScriptLiteralDenyPolicyID))
			b = binary.BigEndian.AppendUint32(b, uint32(len(selected.entries)))
			for _, entry := range selected.entries {
				b = operationalFrame(b, []byte(entry.id))
				b = operationalFrame(b, []byte(entry.literal))
			}
		default:
			return [32]byte{}, false
		}
	}
	return sha256.Sum256(b), true
}

// operationalAdmissionContent copies what this Service would enforce and
// names it. The caller holds Service.mu.
func (s *Service) operationalAdmissionContent() (trust egsmodel.RuntimeTrustPolicy, verifier ed25519Verifier,
	policy admissionPolicySet, digest [32]byte, ok bool) {
	if !s.trustModelVerified || s.trustModelOwner != s || s.trustModel == nil || s.provenanceVerifier == nil ||
		s.trustModel.Validate() != nil {
		return trust, verifier, policy, digest, false
	}
	trustBytes, err := json.Marshal(s.trustModel)
	if err != nil || int64(len(trustBytes)) > maxDependencyJSONResponseBytes {
		return trust, verifier, policy, digest, false
	}
	configured := s.provenanceVerifier
	if configured.algorithm != "ed25519" || strings.TrimSpace(configured.keyID) == "" ||
		len(configured.publicKey) != ed25519.PublicKeySize {
		return trust, verifier, policy, digest, false
	}
	if cfg := s.cfg.AdmissionPolicy; cfg != nil && cfg.Validate() != nil {
		return trust, verifier, policy, digest, false
	}
	expected, typeOK := admissionPolicyEvaluatorFromConfig(s.cfg.AdmissionPolicy).(admissionPolicySet)
	if !typeOK {
		return trust, verifier, policy, digest, false
	}
	var selected admissionPolicySet
	if s.admissionPolicyEvaluator == nil {
		selected, ok = copyOperationalPolicySet(expected)
	} else {
		actual, isSet := s.admissionPolicyEvaluator.(admissionPolicySet)
		if !isSet {
			return trust, verifier, policy, digest, false
		}
		selected, ok = copyOperationalPolicySet(actual)
		if ok && !operationalPolicyEquals(selected, expected) {
			ok = false
		}
	}
	if !ok {
		return trust, verifier, policy, digest, false
	}
	// The view enforces the normalized lists, and the digest is taken over
	// exactly these values. Normalized returns newly allocated lists, so the
	// view shares no backing array with the Service's own trust model.
	trust = s.trustModel.Normalized()
	verifier = ed25519Verifier{
		algorithm: configured.algorithm,
		keyID:     configured.keyID,
		publicKey: append(ed25519.PublicKey(nil), configured.publicKey...),
	}
	digest, ok = operationalAdmissionDigest(trust, verifier, selected)
	if !ok {
		return egsmodel.RuntimeTrustPolicy{}, ed25519Verifier{}, admissionPolicySet{}, [32]byte{}, false
	}
	return trust, verifier, selected, digest, true
}

// installOperationalAdmission is the one place a view is created. The store
// write runs without Service.mu, and the view is installed only after that
// transaction has ended, with the token the store returned for exactly the
// content this Service copied. It must not be called inside a writer turn.
func (s *Service) installOperationalAdmission(ctx context.Context, d *operationalDomain,
	write func(digest [32]byte) (reliablesubmit.OperationalAdmissionToken, error)) error {
	if s == nil || d == nil || d.self != d || d.custody == nil || write == nil ||
		d.realm.installation == [32]byte{} || d.realm.epoch == 0 || ctx.Err() != nil {
		return errOperationalAdmissionCommission
	}
	s.mu.RLock()
	sampled := s.trustModel
	stopped := s.operationalAdmission != nil || s.operationalWithdrawn || s.operationalSuperseded
	trust, verifier, policy, digest, ok := s.operationalAdmissionContent()
	s.mu.RUnlock()
	if stopped || !ok {
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
	if s.operationalAdmission != nil || s.operationalWithdrawn || s.operationalSuperseded ||
		s.trustModel != sampled || s.trustModelOwner != s || !s.trustModelVerified {
		return errOperationalAdmissionCommission
	}
	s.operationalAdmission = &operationalAdmissionSnapshot{
		owner: s, installation: d.realm.installation, epoch: d.realm.epoch, token: token,
		trust: trust, verifier: verifier, policy: policy, proof: s.operationalProof,
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
// stays stopped and the call may be repeated. Service.mu is not held across
// the store write, and it must not be called inside a writer turn.
func (s *Service) withdrawOperationalEffects(ctx context.Context, d *operationalDomain) bool {
	if s == nil || d == nil || d.self != d || d.custody == nil {
		return false
	}
	s.mu.Lock()
	view := s.operationalAdmission
	if view == nil || view.owner != s || view.installation != d.realm.installation || view.epoch != d.realm.epoch {
		s.mu.Unlock()
		return false
	}
	s.operationalWithdrawn = true
	s.mu.Unlock()
	return d.custody.WithdrawOperationalAdmission(ctx, view.token) == nil
}

// confirmOperationalAdmission asks EGS for the signed trust model and
// compares it, through the admission digest, with the content this process
// holds. Equal content records the time sampled before the request was sent.
// Different content latches supersession for the life of the process. A
// failed request changes nothing, so the deadline keeps running. It performs
// network I/O and is called outside every writer turn, Service.mu and the
// owner mutex. At the two pre-checks the caller holds the custody read lock
// of the borrow across it.
func (s *Service) confirmOperationalAdmission(ctx context.Context) {
	if s == nil {
		return
	}
	s.mu.RLock()
	view := s.operationalAdmission
	stopped := view == nil || view.owner != s || s.operationalWithdrawn || s.operationalSuperseded
	s.mu.RUnlock()
	// A Service that cannot ask EGS cannot confirm; its deadline keeps running.
	if stopped || s.egsClient == nil || s.egsClient.client == nil || s.trustModelVerifier == nil {
		return
	}
	started := time.Now()
	trust, err := s.fetchVerifiedTrustModel(ctx)
	if err != nil {
		return
	}
	digest, ok := operationalAdmissionDigest(trust, view.verifier, view.policy)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.operationalAdmission != view {
		return
	}
	if !view.token.Names(view.installation, view.epoch, digest) {
		s.operationalSuperseded = true
		return
	}
	if started.After(s.operationalConfirmed) {
		s.operationalConfirmed = started
	}
}

// operationalConfirmationFresh requires a confirmation, and less than the
// limit elapsed since it on both the monotonic and the wall clock, with
// neither reading negative. The proof seam can only add elapsed time; a
// negative skew refuses.
func operationalConfirmationFresh(confirmed, now time.Time, proof *operationalAdmissionProofHooks) bool {
	if confirmed.IsZero() {
		return false
	}
	var skew time.Duration
	if proof != nil && proof.skew != nil {
		if skew = proof.skew(); skew < 0 {
			return false
		}
	}
	for _, elapsed := range [2]time.Duration{now.Sub(confirmed), now.Round(0).Sub(confirmed.Round(0))} {
		if elapsed < 0 || elapsed >= operationalAdmissionConfirmationLimit ||
			skew >= operationalAdmissionConfirmationLimit-elapsed {
			return false
		}
	}
	return true
}

// currentOperationalAdmission returns the view only while it may be used: it
// exists for this realm, is neither withdrawn nor superseded, and its last
// confirmation is within the limit. Every sample point inherits all of it.
func (s *Service) currentOperationalAdmission(realm operationalRealm) (*operationalAdmissionSnapshot, bool) {
	if s == nil {
		return nil, false
	}
	s.mu.RLock()
	snapshot := s.operationalAdmission
	stopped := snapshot == nil || snapshot.owner != s || s.operationalWithdrawn || s.operationalSuperseded ||
		snapshot.installation != realm.installation || snapshot.epoch != realm.epoch
	confirmed := s.operationalConfirmed
	s.mu.RUnlock()
	if stopped || !operationalConfirmationFresh(confirmed, time.Now(), snapshot.proof) {
		return nil, false
	}
	return snapshot, true
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
	snapshot, ok := s.currentOperationalAdmission(realm)
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
	if evidencev1.Verify(evidence, snapshot.verifier.keyID, snapshot.verifier.algorithm,
		snapshot.verifier.publicKey) != nil {
		return reliablesubmit.OperationalDenied
	}
	if enforceTrustModel(snapshot.trust, evidence.Seal.KeyID,
		evidence.Claims.Package.Identity.ArtifactDigest) != nil {
		return reliablesubmit.OperationalDenied
	}
	artifact := preparedArtifact{
		manifest:       manifestFromEvidence(evidence),
		payloadDigest:  evidence.Claims.Package.Identity.PayloadDigest,
		targetPlatform: evidence.Claims.Admission.Execution.Workload.TargetPlatform,
		networkAccess:  evidence.Claims.Admission.Execution.Access.NetworkAccess,
	}
	policyCtx := newAdmissionPolicyContext(original.delivery.request, artifact)
	required := snapshot.policy.RequiredInputClasses(policyCtx)
	if snapshot.proof != nil && snapshot.proof.required != nil {
		snapshot.proof.required(slices.Clone(required))
	}
	if !completeOperationalPolicyInputs(&policyCtx, required, original.resolved.material.payloadBytes) {
		return reliablesubmit.OperationalUnavailable
	}
	if snapshot.proof != nil && snapshot.proof.contextObserved != nil {
		observed := policyCtx
		observed.InvocationArgv = slices.Clone(policyCtx.InvocationArgv)
		snapshot.proof.contextObserved(observed)
	}
	decision := snapshot.policy.Evaluate(ctx, policyCtx)
	if snapshot.proof != nil && snapshot.proof.evaluated != nil {
		snapshot.proof.evaluated(decision.Allow)
	}
	if !decision.Allow {
		return reliablesubmit.OperationalDenied
	}
	if ctx.Err() != nil {
		return reliablesubmit.OperationalCanceled
	}
	// Withdrawal, supersession or the deadline can arrive during bounded
	// local evaluation.
	if current, still := s.currentOperationalAdmission(realm); !still || current != snapshot {
		return reliablesubmit.OperationalUnavailable
	}
	return reliablesubmit.OperationalReasonNone
}
