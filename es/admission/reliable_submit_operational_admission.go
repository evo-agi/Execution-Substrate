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
	"unicode/utf8"

	egsmodel "execution-substrate/egs/model"
	"execution-substrate/es/admission/internal/reliablesubmit"
	evidencev1 "execution-substrate/internal/contracts/evidence/v1"
)

const maxOperationalEvidenceBytes = 256 * 1024

var errOperationalAdmissionCommission = errors.New("private operational admission unavailable")

// operationalAdmissionSnapshot is immutable after its one-shot installation.
// Its owner link prevents a copy of Service from borrowing the authority.
type operationalAdmissionSnapshot struct {
	owner        *Service
	installation [32]byte
	epoch        uint64
	trust        egsmodel.RuntimeTrustPolicy
	verifier     ed25519Verifier
	policy       admissionPolicySet
	proof        *operationalAdmissionProofHooks
}

// Nil in production. Tests may count calls made by the selected built-in set.
type operationalAdmissionProofHooks struct {
	required        func([]AdmissionPolicyInputClass)
	evaluated       func(bool)
	contextObserved func(AdmissionPolicyContext)
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

// commissionOperationalAdmission is private and has no production caller.
// A fixture may present its explicitly verified trust setup to this method.
func (s *Service) commissionOperationalAdmission(realm operationalRealm) error {
	if s == nil || realm.installation == [32]byte{} || realm.epoch == 0 {
		return errOperationalAdmissionCommission
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.operationalAdmission != nil || s.operationalWithdrawn || !s.trustModelVerified ||
		s.trustModelOwner != s || s.trustModel == nil || s.provenanceVerifier == nil {
		return errOperationalAdmissionCommission
	}
	if err := s.trustModel.Validate(); err != nil {
		return errOperationalAdmissionCommission
	}
	trustBytes, err := json.Marshal(s.trustModel)
	if err != nil || int64(len(trustBytes)) > maxDependencyJSONResponseBytes {
		return errOperationalAdmissionCommission
	}
	verifier := s.provenanceVerifier
	if verifier.algorithm != "ed25519" || strings.TrimSpace(verifier.keyID) == "" ||
		len(verifier.publicKey) != ed25519.PublicKeySize {
		return errOperationalAdmissionCommission
	}
	if cfg := s.cfg.AdmissionPolicy; cfg != nil {
		if err := cfg.Validate(); err != nil {
			return errOperationalAdmissionCommission
		}
	}
	expected, ok := admissionPolicyEvaluatorFromConfig(s.cfg.AdmissionPolicy).(admissionPolicySet)
	if !ok {
		return errOperationalAdmissionCommission
	}
	var selected admissionPolicySet
	if s.admissionPolicyEvaluator == nil {
		selected, ok = copyOperationalPolicySet(expected)
	} else {
		actual, typeOK := s.admissionPolicyEvaluator.(admissionPolicySet)
		if !typeOK {
			return errOperationalAdmissionCommission
		}
		selected, ok = copyOperationalPolicySet(actual)
		if ok && !operationalPolicyEquals(selected, expected) {
			ok = false
		}
	}
	if !ok {
		return errOperationalAdmissionCommission
	}
	s.operationalAdmission = &operationalAdmissionSnapshot{
		owner: s, installation: realm.installation, epoch: realm.epoch,
		trust: snapshotRuntimeTrustModel(*s.trustModel),
		verifier: ed25519Verifier{
			algorithm: verifier.algorithm,
			keyID:     verifier.keyID,
			publicKey: append(ed25519.PublicKey(nil), verifier.publicKey...),
		},
		policy: selected,
		proof:  s.operationalProof,
	}
	return nil
}

// withdrawOperationalEffects is monotonic and does not take custody or SQLite.
func (s *Service) withdrawOperationalEffects() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.operationalAdmission == nil || s.operationalAdmission.owner != s {
		return false
	}
	s.operationalWithdrawn = true
	return true
}

func (s *Service) currentOperationalAdmission(realm operationalRealm) (*operationalAdmissionSnapshot, bool) {
	if s == nil {
		return nil, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	snapshot := s.operationalAdmission
	if snapshot == nil || snapshot.owner != s || s.operationalWithdrawn ||
		snapshot.installation != realm.installation || snapshot.epoch != realm.epoch {
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

func (s *Service) qualifyOperationalRetained(ctx context.Context, original verifiedOperationalOriginal,
	realm operationalRealm) reliablesubmit.OperationalReason {
	if ctx.Err() != nil {
		return reliablesubmit.OperationalCanceled
	}
	if original.variant != operationalOriginalV2 {
		return reliablesubmit.OperationalUnavailable
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
		return reliablesubmit.OperationalIntegrity
	}
	if enforceTrustModel(snapshot.trust, evidence.Seal.KeyID,
		evidence.Claims.Package.Identity.ArtifactDigest) != nil {
		return reliablesubmit.OperationalUnavailable
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
		return reliablesubmit.OperationalUnavailable
	}
	if ctx.Err() != nil {
		return reliablesubmit.OperationalCanceled
	}
	// Withdrawal can occur during bounded local evaluation.
	if current, still := s.currentOperationalAdmission(realm); !still || current != snapshot {
		return reliablesubmit.OperationalUnavailable
	}
	return reliablesubmit.OperationalReasonNone
}
