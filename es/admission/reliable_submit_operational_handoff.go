package admission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net/http"
	"sync"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"golang.org/x/sys/unix"

	"execution-substrate/es/admission/internal/reliablesubmit"
)

func (s *Service) composeOperationalOriginal(ctx context.Context, delivery privateReplayDelivery, keys operationalOriginalKeys,
	realm operationalRealm) (verifiedOperationalOriginal, error) {
	resolved, resolveErr := s.resolveExecutionForSubmit(ctx, delivery.request)
	if resolveErr != nil || !validateOperationalPlan(delivery, resolved, realm) {
		return verifiedOperationalOriginal{}, errPrivateReplayUnavailable
	}
	assessment, err := buildReliableSubmitAdmissionBinding(resolved, delivery.family, keys.key)
	if err != nil {
		return verifiedOperationalOriginal{}, errPrivateReplayUnavailable
	}
	wire, err := encodeOperationalOriginal(delivery, resolved, assessment, keys, realm)
	if err != nil {
		return verifiedOperationalOriginal{}, err
	}
	return verifiedOperationalOriginal{delivery: delivery, resolved: resolved, assessment: assessment, wire: wire}, nil
}

type operationalResultKind uint8

const (
	operationalUnavailable operationalResultKind = iota
	operationalUnauthorized
	operationalConflict
	operationalPending
	operationalAmbiguous
	operationalAccepted
)

type operationalHandoffResult struct {
	privateExecutionValue
	kind      operationalResultKind
	run       string
	receipt   reliablesubmit.ReceiptRef
	reason    reliablesubmit.OperationalReason
	operation reliablesubmit.OperationalOperation
	write     reliablesubmit.OperationalDisposition
}

func operationalFailure(reason reliablesubmit.OperationalReason) operationalHandoffResult {
	return operationalHandoffResult{kind: operationalUnavailable, reason: reason}
}

func operationalFailureAt(ctx context.Context, reason reliablesubmit.OperationalReason) operationalHandoffResult {
	if ctx.Err() != nil {
		reason = reliablesubmit.OperationalCanceled
	}
	return operationalFailure(reason)
}

func (r operationalHandoffResult) withWrite(op reliablesubmit.OperationalOperation, write reliablesubmit.OperationalDisposition) operationalHandoffResult {
	r.operation, r.write = op, write
	return r
}

func (r operationalHandoffResult) withhold(reason reliablesubmit.OperationalReason) operationalHandoffResult {
	r.kind, r.run, r.receipt, r.reason = operationalUnavailable, "", reliablesubmit.ReceiptRef{}, reason
	return r
}

// Tests can order real collaborators and model the observed cleanup result.
// A nil hook is the ordinary path; none can grant authority.
type operationalHandoffProofHooks struct {
	beforeEstablish   func()
	afterEstablish    func()
	beforePrestage    func()
	beforeStageCreate func()
	beforeMaterialize func()
	beforeStamp       func()
	beforeMarker      func()
	afterStageClose   func(error) error
	beforeConsume     func(*liveSender, *handoffOwner)
	beforeEntrySample func()
}

type operationalDomain struct {
	privateExecutionValue
	self     *operationalDomain
	custody  *reliablesubmit.OperationalCustody
	provider *operationalProvider
	stage    *qualifiedDirectory
	realm    operationalRealm
	keys     operationalOriginalKeys
	caller   spiffeid.ID
	proof    *operationalHandoffProofHooks
}

func newOperationalDomain(c *reliablesubmit.OperationalCustody, p *operationalProvider, keys operationalOriginalKeys, caller spiffeid.ID) (*operationalDomain, error) {
	if c == nil || p == nil || caller.String() == "" || !keys.key.validated {
		return nil, errPrivateReplayUnavailable
	}
	stage, err := openQualifiedDirectoryExact(p.realm.staging)
	if err != nil {
		return nil, errPrivateReplayUnavailable
	}
	if _, err := qualifyOperationalStageParent(stage, stage.identity, p.realm.owner); err != nil {
		_ = stage.close()
		return nil, errPrivateReplayUnavailable
	}
	d := &operationalDomain{custody: c, provider: p, stage: stage, realm: p.realm, keys: keys, caller: caller}
	d.self = d
	return d, nil
}

func (d *operationalDomain) eligible() bool {
	if d == nil || d.self != d || d.provider == nil || d.realm != d.provider.realm || d.stage == nil {
		return false
	}
	_, err := qualifyOperationalStageParent(d.stage, d.stage.identity, d.realm.owner)
	return err == nil
}

func (d *operationalDomain) close() error {
	if d == nil || d.self != d || d.stage == nil {
		return errPrivateReplayUnavailable
	}
	return d.stage.close()
}

func (s *Service) handoffOperational(ctx context.Context, d *operationalDomain, peer spiffeid.ID, raw []byte) operationalHandoffResult {
	return s.operatePrivateHandoff(ctx, d, peer, raw, false)
}

func (s *Service) recoverOperational(ctx context.Context, d *operationalDomain, peer spiffeid.ID, raw []byte) operationalHandoffResult {
	return s.operatePrivateHandoff(ctx, d, peer, raw, true)
}

func (s *Service) operatePrivateHandoff(ctx context.Context, d *operationalDomain, peer spiffeid.ID, raw []byte, recovery bool) operationalHandoffResult {
	if d == nil || d.self != d || peer.String() == "" || peer != d.caller {
		return operationalHandoffResult{kind: operationalUnauthorized}
	}
	parserCaller, err := newSyntheticCallerFact(peer.String())
	if err != nil {
		return operationalHandoffResult{kind: operationalUnauthorized}
	}
	delivery, err := parsePrivateReplayDelivery(raw, parserCaller)
	if err != nil {
		return operationalFailure(reliablesubmit.OperationalMalformed)
	}
	canonical, err := privateIncomingIntent(delivery)
	if err != nil {
		return operationalFailure(reliablesubmit.OperationalMalformed)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	outcome := operationalFailure(reliablesubmit.OperationalUnavailable)
	withOriginal := func(read reliablesubmit.OperationalOriginalRead, advance, observe bool) reliablesubmit.OperationalCheck {
		var original verifiedOperationalOriginal
		return d.custody.WithOperationalOriginal(ctx, delivery.refs.claimID, d.keys.storage, canonical, read,
			func(view *reliablesubmit.OperationalOriginalView) (reliablesubmit.OperationalOriginalMatch, error) {
				fields, err := view.Fields()
				if err != nil || len(fields) != 11 {
					return reliablesubmit.OperationalOriginalMatch{}, errPrivateReplayUnavailable
				}
				e := privateReplayEncoder{}
				body := encodeProgressOriginalObject(&e, fields)
				if e.err != nil {
					return reliablesubmit.OperationalOriginalMatch{}, errPrivateReplayUnavailable
				}
				wire := binary.BigEndian.AppendUint16([]byte("ESRSPAY3"), 3)
				wire = binary.BigEndian.AppendUint32(wire, uint32(len(body)))
				original, err = verifyOperationalOriginal(append(wire, body...), d.keys, d.realm)
				if err != nil {
					return reliablesubmit.OperationalOriginalMatch{}, err
				}
				return reliablesubmit.MatchOperationalOriginal(original.delivery.refs.claimID, original.assessment.boundPlan, original.wire)
			}, func(access *reliablesubmit.OperationalAccess, p reliablesubmit.OperationalProjection) {
				outcome = d.advanceOperational(ctx, access, p, original, advance, observe)
			})
	}
	existing := withOriginal(reliablesubmit.OperationalRetainedRead, !recovery, true)
	switch existing.Disposition() {
	case reliablesubmit.OperationalCurrent:
		return outcome
	case reliablesubmit.OperationalConflict:
		return operationalHandoffResult{kind: operationalConflict, reason: existing.Reason()}
	case reliablesubmit.OperationalAbsent:
		if recovery {
			return operationalFailure(reliablesubmit.OperationalUnavailable)
		}
	default:
		return operationalFailure(existing.Reason())
	}
	if !d.eligible() {
		return operationalFailureAt(ctx, reliablesubmit.OperationalIntegrity)
	}
	if d.proof != nil && d.proof.beforeEstablish != nil {
		d.proof.beforeEstablish()
	}
	original, err := s.composeOperationalOriginal(ctx, delivery, d.keys, d.realm)
	if err != nil {
		return operationalFailureAt(ctx, reliablesubmit.OperationalUnavailable)
	}
	first := d.custody.EstablishOperational(ctx, delivery.refs.claimID, original.assessment.boundPlan, d.keys.storage, original.wire)
	if d.proof != nil && d.proof.afterEstablish != nil {
		d.proof.afterEstablish()
	}
	switch first.Disposition() {
	case reliablesubmit.OperationalOccupied:
		winner := withOriginal(reliablesubmit.OperationalRetainedRead, false, false)
		switch winner.Disposition() {
		case reliablesubmit.OperationalCurrent:
			if outcome.reason == reliablesubmit.OperationalReasonNone {
				outcome.reason = first.Reason()
			}
		case reliablesubmit.OperationalConflict:
			outcome = operationalHandoffResult{kind: operationalConflict, reason: winner.Reason()}
		default:
			outcome = operationalFailure(winner.Reason())
		}
		return outcome.withWrite(reliablesubmit.OperationalEstablish, first.Disposition())
	case reliablesubmit.OperationalApplied, reliablesubmit.OperationalOwnCommitConfirmed:
		released := withOriginal(reliablesubmit.OperationalEstablishmentRead, first.Disposition() == reliablesubmit.OperationalApplied, false)
		if released.Disposition() != reliablesubmit.OperationalCurrent {
			disposition := reliablesubmit.OperationalAppliedReleaseFailed
			if first.Disposition() == reliablesubmit.OperationalOwnCommitConfirmed {
				disposition = reliablesubmit.OperationalUnknown
			}
			return operationalFailureAt(ctx, released.Reason()).withWrite(reliablesubmit.OperationalEstablish, disposition)
		}
		if outcome.operation == 0 {
			return outcome.withWrite(reliablesubmit.OperationalEstablish, first.Disposition())
		}
		return outcome
	default:
		return operationalFailure(first.Reason()).withWrite(reliablesubmit.OperationalEstablish, first.Disposition())
	}
}

func operationalReadProjection(p reliablesubmit.OperationalProjection) operationalHandoffResult {
	run, _, _ := p.Locator()
	_, _, _, marker, _ := p.Bindings()
	if marker != [32]byte{} {
		return operationalHandoffResult{kind: operationalAmbiguous, run: run}
	}
	return operationalHandoffResult{kind: operationalPending, run: run}
}

func (d *operationalDomain) advanceOperational(ctx context.Context, a *reliablesubmit.OperationalAccess, p reliablesubmit.OperationalProjection,
	original verifiedOperationalOriginal, advance, observe bool) (out operationalHandoffResult) {
	out = operationalReadProjection(p)
	qualify := func() (reliablesubmit.OperationalOriginalMatch, error) {
		if !d.eligible() || !validateOperationalPlan(original.delivery, original.resolved, d.realm) {
			return reliablesubmit.OperationalOriginalMatch{}, errPrivateReplayUnavailable
		}
		return reliablesubmit.MatchOperationalOriginal(original.delivery.refs.claimID, original.assessment.boundPlan, original.wire)
	}
	if p.Revision() == 1 {
		if !advance {
			return out
		}
		if _, err := qualify(); err != nil {
			return out.withhold(reliablesubmit.OperationalIntegrity)
		}
		m, err := reliablesubmit.NewOperationalMutation()
		if err != nil {
			return out
		}
		command, err := reliablesubmit.NewAssignOperationalRun()
		if err != nil {
			return out
		}
		status, current := a.Apply(ctx, p, m, command, qualify)
		if status != reliablesubmit.OperationalApplied {
			return stoppedOperational(ctx, reliablesubmit.OperationalAssign, status, current)
		}
		p = current
		out = operationalReadProjection(p).withWrite(reliablesubmit.OperationalAssign, status)
	}
	runID, jobID, ok := p.Locator()
	if !ok {
		return out
	}
	run := newResolvedRunProjection(original.resolved.plan, original.resolved.host, executionLocator{RunID: runID, jobID: jobID})
	job, err := d.provider.project(run, jobID)
	if err != nil {
		return out.withhold(reliablesubmit.OperationalIntegrity)
	}
	if p.Receipt().Valid() {
		if a.VerifyOperationalReceipt(p, job.project, job.locator) {
			return operationalHandoffResult{kind: operationalAccepted, run: runID, receipt: p.Receipt()}
		}
		return operationalFailure(reliablesubmit.OperationalIntegrity)
	}
	originalRef, intent, stamp, marker, _ := p.Bindings()
	wantIntent := append([]byte("ESOHINT1"), originalRef[:]...)
	wantIntent = operationalFrame(wantIntent, []byte(runID))
	intentRef := sha256.Sum256(append(wantIntent, job.locator[:]...))
	if p.Revision() >= 3 && intent != intentRef {
		return operationalFailure(reliablesubmit.OperationalIntegrity)
	}
	if marker != [32]byte{} {
		if observe {
			return d.reconcileOperational(ctx, a, p, job, operationalAck{})
		}
		return out
	}
	if !advance || stamp != [32]byte{} {
		return out
	}
	if _, err := qualify(); err != nil {
		return out.withhold(reliablesubmit.OperationalIntegrity)
	}
	if p.Revision() == 2 {
		m, err := reliablesubmit.NewOperationalMutation()
		if err != nil {
			return out.withhold(reliablesubmit.OperationalIntegrity)
		}
		command, err := a.BindOperationalIntent(p, job.locator)
		if err != nil {
			return out.withhold(reliablesubmit.OperationalIntegrity)
		}
		status, current := a.Apply(ctx, p, m, command, qualify)
		if status != reliablesubmit.OperationalApplied {
			return stoppedOperational(ctx, reliablesubmit.OperationalIntent, status, current)
		}
		p = current
		out = operationalReadProjection(p).withWrite(reliablesubmit.OperationalIntent, status)
	}
	if d.proof != nil && d.proof.beforePrestage != nil {
		d.proof.beforePrestage()
	}
	prestage := a.Prestage(ctx, p, qualify)
	if prestage.Disposition() != reliablesubmit.OperationalNoChange ||
		prestage.Reason() != reliablesubmit.OperationalReasonNone {
		reason := prestage.Reason()
		if reason == reliablesubmit.OperationalReasonNone {
			reason = reliablesubmit.OperationalIntegrity
		}
		return out.withhold(reason)
	}
	if d.proof != nil && d.proof.beforeStageCreate != nil {
		d.proof.beforeStageCreate()
	}
	held, err := d.createOperationalStage(runID)
	if errors.Is(err, errOperationalStageOccupied) {
		out.reason = reliablesubmit.OperationalOccupiedReason
		return out
	}
	if err != nil {
		return out.withhold(reliablesubmit.OperationalIntegrity)
	}
	defer func() {
		err := held.close()
		if d.proof != nil && d.proof.afterStageClose != nil {
			err = d.proof.afterStageClose(err)
		}
		if err != nil {
			out = out.withhold(reliablesubmit.OperationalClosed)
		}
	}()
	if d.proof != nil && d.proof.beforeMaterialize != nil {
		d.proof.beforeMaterialize()
	}
	if _, failure := materializeExecutionInputs(held, run, original.resolved.material); failure != nil {
		return out.withhold(reliablesubmit.OperationalIntegrity)
	}
	if d.proof != nil && d.proof.beforeStamp != nil {
		d.proof.beforeStamp()
	}
	var parentLinks uint64
	first, err := measureOperationalStage(held, original.resolved.material, originalRef, runID, intentRef, job.project, &parentLinks, true)
	if err != nil {
		return out.withhold(reliablesubmit.OperationalIntegrity)
	}
	stage, err := a.BindOperationalStage(p, job.project, job.locator, first, func() ([]byte, error) {
		return measureOperationalStage(held, original.resolved.material, originalRef, runID, intentRef, job.project, &parentLinks, false)
	})
	if err != nil {
		return out.withhold(reliablesubmit.OperationalIntegrity)
	}
	move, err := reliablesubmit.NewOperationalMutation()
	if err != nil {
		return out.withhold(reliablesubmit.OperationalIntegrity)
	}
	status, current := a.Apply(ctx, p, move, stage, qualify)
	if status != reliablesubmit.OperationalApplied {
		return stoppedOperational(ctx, reliablesubmit.OperationalStamp, status, current)
	}
	p = current
	out = operationalReadProjection(p).withWrite(reliablesubmit.OperationalStamp, status)
	if d.proof != nil && d.proof.beforeMarker != nil {
		d.proof.beforeMarker()
	}
	move, err = reliablesubmit.NewOperationalMutation()
	if err != nil {
		return out.withhold(reliablesubmit.OperationalIntegrity)
	}
	candidate, err := a.BindOperationalMarker(p, move, stage)
	if err != nil {
		return out.withhold(reliablesubmit.OperationalIntegrity)
	}
	_, _, stamp, _, _ = p.Bindings()
	marker = candidate.Ref()
	body, err := job.request(job.carrierForMarker(d.keys.key.bytes, p, marker))
	if err != nil {
		return out.withhold(reliablesubmit.OperationalIntegrity)
	}
	binding := operationalDispatchBinding{original: originalRef, run: runID, stamp: stamp, marker: marker,
		project: job.project, locator: job.locator, request: sha256.Sum256(body)}
	owner := &handoffOwner{domain: d, stage: held, proof: stage, context: ctx, binding: binding, open: true}
	var ack operationalAck
	status, current = a.ApplyFirstMarker(ctx, p, move, candidate, qualify, func(applied reliablesubmit.OperationalProjection) {
		actualOriginal, _, stageRef, actual, _ := applied.Bindings()
		actualRun, actualJob, ok := applied.Locator()
		if !ok || actualOriginal != binding.original || actualRun != binding.run || actualJob != job.name || stageRef != binding.stamp || actual != binding.marker {
			return
		}
		sender := &liveSender{owner: owner, issuer: d, prepared: bytes.Clone(body), binding: binding}
		sender.self = sender
		defer owner.close()
		if d.proof != nil && d.proof.beforeConsume != nil {
			d.proof.beforeConsume(sender, owner)
		}
		ack = sender.consume(owner)
	})
	owner.close()
	if status != reliablesubmit.OperationalMarkerDirect {
		return stoppedOperational(ctx, reliablesubmit.OperationalMark, status, current)
	}
	result := d.reconcileOperational(ctx, a, current, job, ack)
	if result.operation == 0 {
		return result.withWrite(reliablesubmit.OperationalMark, status)
	}
	return result
}

func stoppedOperational(ctx context.Context, op reliablesubmit.OperationalOperation, status reliablesubmit.OperationalDisposition,
	current reliablesubmit.OperationalProjection) operationalHandoffResult {
	var out operationalHandoffResult
	switch status {
	case reliablesubmit.OperationalOwnCommitConfirmed, reliablesubmit.OperationalStale, reliablesubmit.OperationalExactReplay,
		reliablesubmit.OperationalDefinitelyNotApplied:
		out = operationalFailureAt(ctx, reliablesubmit.OperationalUnavailable)
		if current.Revision() != 0 {
			out = operationalReadProjection(current)
		}
		if status == reliablesubmit.OperationalStale {
			out.reason = reliablesubmit.OperationalStaleReason
		}
	case reliablesubmit.OperationalConflict:
		out = operationalHandoffResult{kind: operationalConflict, reason: reliablesubmit.OperationalIntentConflict}
	case reliablesubmit.OperationalRefused, reliablesubmit.OperationalAppliedReleaseFailed:
		out = operationalFailureAt(ctx, reliablesubmit.OperationalIntegrity)
	default:
		out = operationalFailureAt(ctx, reliablesubmit.OperationalUnavailable)
	}
	return out.withWrite(op, status)
}

func (d *operationalDomain) reconcileOperational(ctx context.Context, a *reliablesubmit.OperationalAccess, p reliablesubmit.OperationalProjection,
	job operationalJob, ack operationalAck) operationalHandoffResult {
	out := operationalReadProjection(p)
	if ack.collision || ack.refused || ctx.Err() != nil {
		out.reason = ack.reason
		if ctx.Err() != nil {
			out.reason = reliablesubmit.OperationalCanceled
		}
		return out
	}
	result, reason := d.provider.observe(ctx, job, p, d.keys.key.bytes, ack)
	if reason != reliablesubmit.OperationalReasonNone {
		out.reason = reason
		if ack.reason != reliablesubmit.OperationalReasonNone {
			out.reason = ack.reason
		}
		return out
	}
	proof, err := result.bindOperationalObservation(d.provider, a, p, job, d.keys.key.bytes)
	if err != nil {
		return out.withhold(reliablesubmit.OperationalIntegrity)
	}
	m, err := reliablesubmit.NewOperationalMutation()
	if err != nil {
		return out.withhold(reliablesubmit.OperationalIntegrity)
	}
	status, next := a.Apply(ctx, p, m, proof, nil)
	if status == reliablesubmit.OperationalApplied || status == reliablesubmit.OperationalOwnCommitConfirmed ||
		status == reliablesubmit.OperationalStale || status == reliablesubmit.OperationalExactReplay {
		if a.VerifyOperationalReceipt(next, job.project, job.locator) {
			run, _, _ := next.Locator()
			return (operationalHandoffResult{kind: operationalAccepted, run: run, receipt: next.Receipt()}).withWrite(reliablesubmit.OperationalAccept, status)
		}
		return operationalFailureAt(ctx, reliablesubmit.OperationalIntegrity).withWrite(reliablesubmit.OperationalAccept, status)
	}
	return stoppedOperational(ctx, reliablesubmit.OperationalAccept, status, next)
}

var errOperationalStageOccupied = errors.New("operational stage occupied")

func (d *operationalDomain) createOperationalStage(run string) (*stagingCustody, error) {
	if !d.eligible() || !validCustodyComponent(run) {
		return nil, errPrivateReplayUnavailable
	}
	var existing unix.Stat_t
	if err := unix.Fstatat(d.stage.fd, run, &existing, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		if err == nil {
			return nil, errOperationalStageOccupied
		}
		return nil, errPrivateReplayUnavailable
	}
	parent, err := openQualifiedDirectoryExact(d.stage.path)
	if err != nil {
		return nil, errPrivateReplayUnavailable
	}
	if _, err := qualifyOperationalStageParent(parent, d.stage.identity, d.realm.owner); err != nil {
		_ = parent.close()
		return nil, errPrivateReplayUnavailable
	}
	stage, err := claimStagingCustodyFromQualifiedRoot(parent, run, d.realm.owner)
	if errors.Is(err, unix.EEXIST) {
		return nil, errOperationalStageOccupied
	}
	return stage, err
}

type operationalDispatchBinding struct {
	original, stamp, marker, project, locator, request [32]byte
	run                                                string
}

type handoffOwner struct {
	privateExecutionValue
	mu      sync.Mutex
	domain  *operationalDomain
	stage   *stagingCustody
	proof   *reliablesubmit.OperationalStageProof
	context context.Context
	binding operationalDispatchBinding
	open    bool
}

func (o *handoffOwner) close() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.open = false
}

type liveSender struct {
	privateExecutionValue
	self     *liveSender
	owner    *handoffOwner
	issuer   *operationalDomain
	prepared []byte
	binding  operationalDispatchBinding
}

func (s *liveSender) consume(owner *handoffOwner) operationalAck {
	if s == nil || s.self != s || owner == nil || s.owner != owner || s.issuer != owner.domain {
		return operationalAck{refused: true, reason: reliablesubmit.OperationalClosed}
	}
	prepared, err := s.issuer.provider.prepareExchange(owner.context, http.MethodPost, "/v1/jobs", s.prepared)
	if err == nil {
		defer prepared.cancel()
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if !owner.open {
		return operationalAck{refused: true, reason: reliablesubmit.OperationalClosed}
	}
	owner.open = false
	if err != nil || owner.stage == nil || !owner.domain.eligible() ||
		s.binding != owner.binding || owner.stage.runID != s.binding.run ||
		s.binding.original == [32]byte{} || s.binding.stamp == [32]byte{} || s.binding.marker == [32]byte{} ||
		s.binding.project == [32]byte{} || s.binding.locator == [32]byte{} || len(s.prepared) == 0 ||
		sha256.Sum256(s.prepared) != s.binding.request || !owner.proof.Requalify() {
		return operationalAck{refused: true, reason: reliablesubmit.OperationalIntegrity}
	}
	if proof := owner.domain.proof; proof != nil && proof.beforeEntrySample != nil {
		proof.beforeEntrySample()
	}
	if err := prepared.request.Context().Err(); err != nil {
		return operationalAck{refused: true, reason: operationalExchangeFailure(err)}
	}
	return s.issuer.provider.register(prepared)
}
