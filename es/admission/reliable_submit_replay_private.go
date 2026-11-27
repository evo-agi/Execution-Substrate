package admission

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
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
	progressInput  reliablesubmit.ProgressOriginalInput
	progressPlan   reliablesubmit.BoundPlan
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
	ctx = withDeliveryCaller(ctx, caller.canonicalURI)
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
	proposal, err := s.composePrivateSyntheticReplay(ctx, delivery, catalog.active, image, 1)
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
func (s *Service) composePrivateSyntheticReplay(ctx context.Context, delivery privateReplayDelivery, keys privateSyntheticKeyBundle, image privateSyntheticImagePlacement, scope byte) (privateReplayProposal, error) {
	if !delivery.refs.claimID.Valid() || !delivery.family.validated || !keys.binding.validated ||
		image.issuer == "" || (scope != 1 && scope != 2) {
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
	payload, err := encodePrivateReplayPayload(delivery, resolved, assessment, image, keys.bindingID, keys.envelopeID, scope)
	if err != nil {
		return privateReplayProposal{}, errPrivateReplayUnavailable
	}
	prospective, err := decodePrivateReplayOriginal(payload, keys, scope)
	if err != nil || !prospective.claim.Equal(delivery.refs.claimID) ||
		!prospective.assessment.boundPlan.EqualBinding(assessment.boundPlan.Binding()) {
		return privateReplayProposal{}, errPrivateReplayUnavailable
	}
	if scope == 2 {
		input, err := reliablesubmit.NewProgressOriginalInput(payload)
		if err != nil {
			return privateReplayProposal{}, errPrivateReplayUnavailable
		}
		return privateReplayProposal{progressInput: input, progressPlan: assessment.boundPlan}, nil
	}
	frozen, err := reliablesubmit.NewPrivateReplayFrozen(delivery.refs.claimID, assessment.boundPlan, keys.storage, payload)
	if err != nil {
		return privateReplayProposal{}, errPrivateReplayUnavailable
	}
	return privateReplayProposal{frozen: frozen, originalIntent: delivery.originalIntent}, nil
}

// admitPrivateProgressReplay is the scope-2 fixture entry point. Its
// invocation owns any establishment proof through the confirmation read.
func (s *Service) admitPrivateProgressReplay(ctx context.Context, custody *reliablesubmit.PrivateReplayProgressCustody,
	raw []byte, caller syntheticCallerFact, catalog privateSyntheticKeyCatalog, image privateSyntheticImagePlacement,
	initial reliablesubmit.FixtureProgressPhase) (reliablesubmit.FixtureProgressDisposition, reliablesubmit.FixtureProgress, error) {
	ctx, cancel := context.WithCancel(withDeliveryCaller(ctx, caller.canonicalURI))
	defer cancel()
	delivery, incoming, err := preparePrivateProgressReplay(raw, caller)
	if err != nil {
		return reliablesubmit.FixtureProgressRefused, reliablesubmit.FixtureProgress{}, err
	}
	lookup, err := custody.LookupProgressOriginal(ctx, delivery.refs.claimID)
	if err != nil {
		return reliablesubmit.FixtureProgressRefused, reliablesubmit.FixtureProgress{}, errPrivateReplayUnavailable
	}
	if !lookup.Absent() {
		return readPrivateProgressReplay(ctx, custody, lookup, incoming, catalog, reliablesubmit.ProgressAttempt{}, false)
	}
	proposal, err := s.composePrivateSyntheticReplay(ctx, delivery, catalog.active, image, 2)
	if err != nil {
		return reliablesubmit.FixtureProgressRefused, reliablesubmit.FixtureProgress{}, errPrivateReplayUnavailable
	}
	frozen, err := custody.FreezeProgressOriginal(ctx, lookup, initial, proposal.progressPlan, catalog.active.storage, proposal.progressInput)
	if err != nil {
		return reliablesubmit.FixtureProgressRefused, reliablesubmit.FixtureProgress{}, errPrivateReplayUnavailable
	}
	permit, err := custody.ReserveProgressSealUse(ctx, frozen)
	if err != nil {
		return reliablesubmit.FixtureProgressRefused, reliablesubmit.FixtureProgress{}, errPrivateReplayUnavailable
	}
	sealedObject, err := custody.PublishProgressOriginal(ctx, frozen, permit)
	if err != nil {
		return reliablesubmit.FixtureProgressRefused, reliablesubmit.FixtureProgress{}, errPrivateReplayUnavailable
	}
	if beforePrivateReplayClaimForTest != nil {
		beforePrivateReplayClaimForTest()
	}
	attempt, state, err := custody.EstablishProgress(ctx, frozen, sealedObject)
	switch state {
	case reliablesubmit.FixtureProgressOccupied:
		winner, readErr := custody.LookupProgressOriginal(ctx, delivery.refs.claimID)
		if readErr != nil || winner.Absent() {
			return state, reliablesubmit.FixtureProgress{}, errPrivateReplayUnavailable
		}
		outcome, progress, readErr := readPrivateProgressReplay(ctx, custody, winner, incoming, catalog, reliablesubmit.ProgressAttempt{}, false)
		switch outcome {
		case reliablesubmit.FixtureProgressCurrent:
			return state, progress, readErr
		case reliablesubmit.FixtureProgressConflict:
			return outcome, reliablesubmit.FixtureProgress{}, readErr
		default:
			return state, reliablesubmit.FixtureProgress{}, errPrivateReplayUnavailable
		}
	case reliablesubmit.FixtureProgressCommitted, reliablesubmit.FixtureProgressWriteUnknown:
		return readPrivateProgressReplay(ctx, custody, lookup, incoming, catalog, attempt, true)
	default:
		return state, reliablesubmit.FixtureProgress{}, privateProgressError(state, err)
	}
}

func preparePrivateProgressReplay(raw []byte, caller syntheticCallerFact) (privateReplayDelivery, []byte, error) {
	delivery, err := parsePrivateReplayDelivery(raw, caller)
	if err != nil {
		return privateReplayDelivery{}, nil, errPrivateReplayInvalidDelivery
	}
	incoming, err := privateIncomingIntent(delivery)
	return delivery, incoming, err
}

func progressOriginalKeys(lookup reliablesubmit.ProgressLookup, catalog privateSyntheticKeyCatalog) (privateSyntheticKeyBundle, error) {
	bindingID, envelopeID, ok := lookup.OriginalKeyIDs()
	if !ok {
		return privateSyntheticKeyBundle{}, errPrivateReplayUnavailable
	}
	return catalog.original(bindingID, envelopeID)
}

func readPrivateProgressReplay(ctx context.Context, custody *reliablesubmit.PrivateReplayProgressCustody,
	lookup reliablesubmit.ProgressLookup, incoming []byte, catalog privateSyntheticKeyCatalog, attempt reliablesubmit.ProgressAttempt,
	ownEstablishment bool) (reliablesubmit.FixtureProgressDisposition, reliablesubmit.FixtureProgress, error) {
	var keys privateSyntheticKeyBundle
	if ownEstablishment {
		keys = catalog.active
	} else {
		original, err := progressOriginalKeys(lookup, catalog)
		if err != nil {
			return reliablesubmit.FixtureProgressRefused, reliablesubmit.FixtureProgress{}, err
		}
		keys = original
	}
	var projection reliablesubmit.FixtureProgress
	state, err := custody.WithAuthenticatedProgressOriginal(ctx, lookup, keys.storage, incoming, attempt,
		func(view *reliablesubmit.ProgressOriginalView) (reliablesubmit.ProgressOriginalMatch, error) {
			return verifyPrivateProgressOriginal(view, keys)
		},
		func(access *reliablesubmit.ProgressAccess) error {
			var err error
			projection, err = custody.ReadFixtureProgress(ctx, access)
			return err
		})
	if err != nil && state == reliablesubmit.FixtureProgressCurrent {
		state = reliablesubmit.FixtureProgressRefused
	}
	return state, projection, privateProgressError(state, err)
}

func (s *Service) applyPrivateProgressReplay(ctx context.Context, custody *reliablesubmit.PrivateReplayProgressCustody,
	raw []byte, caller syntheticCallerFact, catalog privateSyntheticKeyCatalog, expected int64,
	mutation reliablesubmit.FixtureMutationRef, command reliablesubmit.FixtureProgressCommand) (reliablesubmit.FixtureProgressDisposition, reliablesubmit.FixtureProgress, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	delivery, incoming, err := preparePrivateProgressReplay(raw, caller)
	if err != nil {
		return reliablesubmit.FixtureProgressRefused, reliablesubmit.FixtureProgress{}, err
	}
	lookup, err := custody.LookupProgressOriginal(ctx, delivery.refs.claimID)
	if err != nil {
		return reliablesubmit.FixtureProgressRefused, reliablesubmit.FixtureProgress{}, errPrivateReplayUnavailable
	}
	keys, err := progressOriginalKeys(lookup, catalog)
	if err != nil {
		return reliablesubmit.FixtureProgressRefused, reliablesubmit.FixtureProgress{}, err
	}
	var projection reliablesubmit.FixtureProgress
	disposition := reliablesubmit.FixtureProgressRefused
	used := false
	state, err := custody.WithAuthenticatedProgressOriginal(ctx, lookup, keys.storage, incoming, reliablesubmit.ProgressAttempt{},
		func(view *reliablesubmit.ProgressOriginalView) (reliablesubmit.ProgressOriginalMatch, error) {
			return verifyPrivateProgressOriginal(view, keys)
		},
		func(access *reliablesubmit.ProgressAccess) error {
			var err error
			used = true
			disposition, projection, err = custody.ApplyFixtureProgress(ctx, access, expected, mutation, command)
			return err
		})
	if used {
		state = disposition
	}
	return state, projection, privateProgressError(state, err)
}

func privateProgressError(state reliablesubmit.FixtureProgressDisposition, err error) error {
	switch state {
	case reliablesubmit.FixtureProgressConflict:
		return errPrivateReplayConflict
	case reliablesubmit.FixtureProgressWriteUnknown:
		return errPrivateReplayCommitUnknown
	}
	if err != nil || state == reliablesubmit.FixtureProgressRefused {
		return errPrivateReplayUnavailable
	}
	return nil
}

// The custody borrow supplies typed fields. The semantic decoder still
// interprets them and independently re-encodes the complete original.
func verifyPrivateProgressOriginal(view *reliablesubmit.ProgressOriginalView, keys privateSyntheticKeyBundle) (reliablesubmit.ProgressOriginalMatch, error) {
	fields, err := view.Fields()
	if err != nil {
		return reliablesubmit.ProgressOriginalMatch{}, errPrivateReplayUnavailable
	}
	encoder := privateReplayEncoder{}
	body := encodeProgressOriginalObject(&encoder, fields)
	if encoder.err != nil {
		return reliablesubmit.ProgressOriginalMatch{}, errPrivateReplayUnavailable
	}
	encoded, err := framePrivateReplayPayload(body, 2)
	if err != nil {
		return reliablesubmit.ProgressOriginalMatch{}, errPrivateReplayUnavailable
	}
	verified, err := decodePrivateReplayOriginal(encoded, keys, 2)
	if err != nil {
		return reliablesubmit.ProgressOriginalMatch{}, errPrivateReplayUnavailable
	}
	return reliablesubmit.NewProgressOriginalMatch(verified.claim, verified.assessment.boundPlan, verified.intentCanonical, sha256.Sum256(encoded))
}

func encodeProgressOriginalObject(encoder *privateReplayEncoder, fields []reliablesubmit.ProgressOriginalField) []byte {
	parts := make([]privateReplayField, len(fields))
	for i, field := range fields {
		kind, err := field.Kind()
		if err != nil {
			encoder.err = errPrivateReplayUnavailable
			return nil
		}
		parts[i] = encoder.optional(uint16(i+1), kind != 0, encodeProgressOriginalField(encoder, field, kind))
	}
	return encoder.object(parts...)
}

func encodeProgressOriginalField(encoder *privateReplayEncoder, field reliablesubmit.ProgressOriginalField, kind byte) []byte {
	switch kind {
	case 0:
		return nil
	case 'o':
		return encodeProgressOriginalObject(encoder, field.Children())
	case 'q':
		children := field.Children()
		items := make([][]byte, len(children))
		for i, child := range children {
			childKind, err := child.Kind()
			if err != nil || childKind == 0 {
				encoder.err = errPrivateReplayUnavailable
				return nil
			}
			items[i] = encodeProgressOriginalField(encoder, child, childKind)
		}
		return encoder.sequence(items, 4096)
	case 'm':
		return encoder.stringMap(field.Strings(), 4096)
	case 's':
		return []byte(field.Text())
	case 'b', '1':
		return []byte{byte(field.Number())}
	case '2':
		return replayUint16(uint16(field.Number()))
	case '4':
		return replayUint32(uint32(field.Number()))
	case '8':
		return replayUint64(field.Number())
	case 'x':
		return field.Bytes()
	case 'd':
		state, count, digest := field.MaterialDescriptor()
		encoded := binary.BigEndian.AppendUint64([]byte{state}, count)
		return append(encoded, digest[:]...)
	default:
		encoder.err = errPrivateReplayUnavailable
		return nil
	}
}
