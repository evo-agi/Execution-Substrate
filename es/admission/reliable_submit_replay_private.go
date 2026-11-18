package admission

import (
	"context"
	"crypto/hmac"
	"errors"

	"execution-substrate/es/admission/internal/reliablesubmit"
)

var (
	errPrivateReplayUnavailable   = errors.New("private replay: unavailable")
	errPrivateReplayConflict      = errors.New("private replay: changed original intent")
	errPrivateReplayCommitUnknown = errors.New("private replay: claim commit outcome unknown")
)

// Only the controlled synthetic concurrency test installs this hook. It is
// nil in every production path and grants no claim/effect authority.
var beforePrivateReplayClaimForTest func()

type privateSyntheticKeyBundle struct {
	privateExecutionValue
	binding    privateBindingKey
	storage    reliablesubmit.PrivateReplayKeys
	bindingID  string
	envelopeID string
}

func newPrivateSyntheticKeyBundle(bindingID string, bindingBytes []byte, envelopeID string, envelopeBytes []byte) (privateSyntheticKeyBundle, error) {
	storage, err := reliablesubmit.NewPrivateReplayKeys(bindingID, bindingBytes, envelopeID, envelopeBytes)
	if err != nil {
		return privateSyntheticKeyBundle{}, errPrivateReplayUnavailable
	}
	binding, err := newPrivateBindingKey(bindingID, bindingBytes)
	if err != nil {
		return privateSyntheticKeyBundle{}, errPrivateReplayUnavailable
	}
	return privateSyntheticKeyBundle{binding: binding, storage: storage, bindingID: bindingID, envelopeID: envelopeID}, nil
}

type privateReplayProposal struct {
	privateExecutionValue
	frozen         reliablesubmit.PrivateReplayFrozen
	originalIntent privateReplayOriginalIntent
}

type privateSyntheticKeyCatalog struct {
	privateExecutionValue
	active privateSyntheticKeyBundle
	byPair map[string]privateSyntheticKeyBundle
}

func replayKeyPair(bindingID, envelopeID string) string { return bindingID + "\x00" + envelopeID }

func newPrivateSyntheticKeyCatalog(active privateSyntheticKeyBundle, retained ...privateSyntheticKeyBundle) (privateSyntheticKeyCatalog, error) {
	if !active.binding.validated {
		return privateSyntheticKeyCatalog{}, errPrivateReplayUnavailable
	}
	catalog := privateSyntheticKeyCatalog{active: active, byPair: make(map[string]privateSyntheticKeyBundle)}
	for _, bundle := range append([]privateSyntheticKeyBundle{active}, retained...) {
		if !bundle.binding.validated || bundle.bindingID == "" || bundle.envelopeID == "" {
			return privateSyntheticKeyCatalog{}, errPrivateReplayUnavailable
		}
		pair := replayKeyPair(bundle.bindingID, bundle.envelopeID)
		if _, duplicate := catalog.byPair[pair]; duplicate {
			return privateSyntheticKeyCatalog{}, errPrivateReplayUnavailable
		}
		catalog.byPair[pair] = bundle
	}
	return catalog, nil
}

func (c privateSyntheticKeyCatalog) original(bindingID, envelopeID string) (privateSyntheticKeyBundle, error) {
	bundle, ok := c.byPair[replayKeyPair(bindingID, envelopeID)]
	if !ok {
		return privateSyntheticKeyBundle{}, errPrivateReplayUnavailable
	}
	return bundle, nil
}

type privateReplayResultKind uint8

const (
	privateReplayEstablished privateReplayResultKind = iota + 1
	privateReplayExact
	privateReplayWinner
	privateReplayOwnUnknownConfirmed
	privateReplayConflict
	privateReplayUnknown
)

type privateReplayResult struct {
	privateExecutionValue
	kind     privateReplayResultKind
	verified privateVerifiedOriginal
}

func loadAndVerifyPrivateReplay(ctx context.Context, custody *reliablesubmit.PrivateReplayCustody, claim reliablesubmit.ClaimID, catalog privateSyntheticKeyCatalog, attempt reliablesubmit.PrivateReplayAttempt) (privateVerifiedOriginal, error) {
	lookup, err := custody.LoadSyntheticClaim(ctx, claim)
	if err != nil || !lookup.Found() {
		return privateVerifiedOriginal{}, errPrivateReplayUnavailable
	}
	bindingID, envelopeID, ok := lookup.OriginalKeyIDs()
	if !ok {
		return privateVerifiedOriginal{}, errPrivateReplayUnavailable
	}
	keys, err := catalog.original(bindingID, envelopeID)
	if err != nil {
		return privateVerifiedOriginal{}, err
	}
	var verified privateVerifiedOriginal
	called := false
	err = custody.WithAuthenticatedClaim(ctx, claim, keys.storage, func(meta reliablesubmit.AuthenticatedClaimMeta, plaintext []byte) error {
		result, verifyErr := verifyPrivateReplayOriginal(meta, plaintext, keys)
		if verifyErr != nil {
			return verifyErr
		}
		result.ownAttempt = meta.MatchesAttempt(attempt)
		verified = result
		called = true
		return nil
	})
	if err != nil || !called {
		return privateVerifiedOriginal{}, errPrivateReplayUnavailable
	}
	return verified, nil
}

func privateIncomingIntent(delivery privateReplayDelivery) ([]byte, error) {
	encoder := privateReplayEncoder{}
	canonical := encoder.original(delivery.originalIntent)
	if encoder.err != nil || len(canonical) == 0 {
		return nil, errPrivateReplayInvalidDelivery
	}
	return canonical, nil
}

// admitPrivateSyntheticReplay has no runtime caller or effect result. A lookup
// precedes active-key choice, defaults, material acquisition and Seal.
func (s *Service) admitPrivateSyntheticReplay(ctx context.Context, custody *reliablesubmit.PrivateReplayCustody, raw []byte, caller syntheticCallerFact, catalog privateSyntheticKeyCatalog, image privateSyntheticImagePlacement) (privateReplayResult, error) {
	delivery, err := parsePrivateReplayDelivery(raw, caller)
	if err != nil {
		return privateReplayResult{}, errPrivateReplayInvalidDelivery
	}
	incoming, err := privateIncomingIntent(delivery)
	if err != nil {
		return privateReplayResult{}, err
	}
	lookup, err := custody.LoadSyntheticClaim(ctx, delivery.refs.claimID)
	if err != nil {
		return privateReplayResult{}, errPrivateReplayUnavailable
	}
	if lookup.Found() {
		verified, err := loadAndVerifyPrivateReplay(ctx, custody, delivery.refs.claimID, catalog, reliablesubmit.PrivateReplayAttempt{})
		if err != nil {
			return privateReplayResult{}, errPrivateReplayUnavailable
		}
		if !hmac.Equal(incoming, verified.intentCanonical) {
			return privateReplayResult{kind: privateReplayConflict}, errPrivateReplayConflict
		}
		return privateReplayResult{kind: privateReplayExact, verified: verified}, nil
	}
	proposal, err := s.composePrivateSyntheticReplay(ctx, delivery, catalog.active, image)
	if err != nil {
		return privateReplayResult{}, errPrivateReplayUnavailable
	}
	grant, err := custody.ReserveSealUse(ctx, proposal.frozen)
	if err != nil {
		return privateReplayResult{}, errPrivateReplayUnavailable
	}
	sealedObject, err := custody.PublishSealedSynthetic(ctx, proposal.frozen, grant)
	if err != nil {
		return privateReplayResult{}, errPrivateReplayUnavailable
	}
	if beforePrivateReplayClaimForTest != nil {
		beforePrivateReplayClaimForTest()
	}
	attempt, created, claimErr := custody.EstablishSyntheticClaim(ctx, proposal.frozen, sealedObject)
	if claimErr != nil && !errors.Is(claimErr, reliablesubmit.ErrPrivateReplayClaimCommitUnknown()) {
		return privateReplayResult{}, errPrivateReplayUnavailable
	}
	verified, verifyErr := loadAndVerifyPrivateReplay(ctx, custody, delivery.refs.claimID, catalog, attempt)
	if verifyErr != nil {
		if claimErr != nil {
			return privateReplayResult{kind: privateReplayUnknown}, errPrivateReplayCommitUnknown
		}
		return privateReplayResult{}, errPrivateReplayUnavailable
	}
	if !privateOriginalIntentEqual(incoming, verified.intentCanonical) {
		return privateReplayResult{kind: privateReplayConflict}, errPrivateReplayConflict
	}
	if claimErr != nil {
		if verified.ownAttempt {
			return privateReplayResult{kind: privateReplayOwnUnknownConfirmed, verified: verified}, nil
		}
		return privateReplayResult{kind: privateReplayWinner, verified: verified}, nil
	}
	if created {
		if !verified.ownAttempt {
			return privateReplayResult{}, errPrivateReplayUnavailable
		}
		return privateReplayResult{kind: privateReplayEstablished, verified: verified}, nil
	}
	return privateReplayResult{kind: privateReplayWinner, verified: verified}, nil
}

// composePrivateSyntheticReplay is the only private caller of the real submit
// resolver and unchanged PB1 producer. It has no runtime or effect caller.
func (s *Service) composePrivateSyntheticReplay(ctx context.Context, delivery privateReplayDelivery, keys privateSyntheticKeyBundle, image privateSyntheticImagePlacement) (privateReplayProposal, error) {
	if !delivery.refs.claimID.Valid() || !delivery.family.validated || !keys.binding.validated ||
		image.issuer == "" {
		return privateReplayProposal{}, errPrivateReplayUnavailable
	}
	resolved, resolveErr := s.resolveExecutionForSubmit(ctx, delivery.request)
	if resolveErr != nil {
		return privateReplayProposal{}, errPrivateReplayUnavailable
	}
	invocationSchema := delivery.request.Invocation.SchemaVersion
	if invocationSchema == "" {
		invocationSchema = "v1"
	}
	if delivery.request.SchemaVersion != "v1" || resolved.plan.requestSchemaVersion != delivery.request.SchemaVersion ||
		resolved.plan.invocationSchemaVersion != invocationSchema ||
		resolved.plan.artifactDigest != delivery.request.Invocation.ArtifactDigest ||
		resolved.plan.derivationSpecDigest != delivery.request.Invocation.DerivationSpecDigest ||
		resolved.plan.outputID != delivery.request.Invocation.OutputID {
		return privateReplayProposal{}, errPrivateReplayUnavailable
	}
	assessment, err := buildReliableSubmitAdmissionBinding(resolved, delivery.family, keys.binding)
	if err != nil || assessment.effectReady {
		return privateReplayProposal{}, errPrivateReplayUnavailable
	}
	payload, err := encodePrivateReplayPayload(delivery, resolved, assessment, image, keys.bindingID, keys.envelopeID)
	if err != nil {
		return privateReplayProposal{}, errPrivateReplayUnavailable
	}
	prospective, err := decodePrivateReplayOriginal(payload, keys)
	if err != nil || !prospective.claim.Equal(delivery.refs.claimID) ||
		!prospective.assessment.boundPlan.EqualBinding(assessment.boundPlan.Binding()) {
		return privateReplayProposal{}, errPrivateReplayUnavailable
	}
	frozen, err := reliablesubmit.NewPrivateReplayFrozen(delivery.refs.claimID, assessment.boundPlan, keys.storage, payload)
	if err != nil {
		return privateReplayProposal{}, errPrivateReplayUnavailable
	}
	return privateReplayProposal{frozen: frozen, originalIntent: delivery.originalIntent}, nil
}
