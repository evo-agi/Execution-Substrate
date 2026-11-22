package reliablesubmit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

func operationalDNSLabel(raw []byte) bool {
	if len(raw) == 0 || len(raw) > 63 {
		return false
	}
	for i, ch := range raw {
		if ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' {
			continue
		}
		if ch != '-' || i == 0 || i == len(raw)-1 {
			return false
		}
	}
	return true
}

func operationalDNSName(raw []byte) bool {
	if len(raw) == 0 || len(raw) > 253 {
		return false
	}
	for _, label := range bytes.Split(raw, []byte{'.'}) {
		if !operationalDNSLabel(label) {
			return false
		}
	}
	return true
}

func operationalDeploymentPath(raw []byte) bool {
	if len(raw) < 2 || len(raw) > 512 || raw[0] != '/' {
		return false
	}
	for _, component := range bytes.Split(raw[1:], []byte{'/'}) {
		if len(component) == 0 || len(component) > 128 || bytes.Equal(component, []byte(".")) || bytes.Equal(component, []byte("..")) {
			return false
		}
		for _, ch := range component {
			if !(ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_' || ch == '.') {
				return false
			}
		}
	}
	return true
}

func (v *replayStructure) operationalDeployment(fields []replayField) error {
	return v.object(fields[10], 15, 2, false, func(d []replayField) error {
		for i, f := range d {
			switch i + 1 {
			case 1:
				if v.scalar(f, '2', 2, false) != nil || binary.BigEndian.Uint16(f.value) != 1 {
					return errReplayFormat
				}
			case 2, 4, 5, 14, 15:
				if v.scalar(f, 'x', 32, false) != nil || !operationalNonzeroRef(f.value) {
					return errReplayFormat
				}
			case 3:
				if v.scalar(f, '8', 8, false) != nil || binary.BigEndian.Uint64(f.value) == 0 {
					return errReplayFormat
				}
			case 6:
				if v.scalar(f, 's', 253, false) != nil || !operationalDNSName(f.value) {
					return errReplayFormat
				}
			case 7:
				if v.scalar(f, '2', 2, false) != nil || binary.BigEndian.Uint16(f.value) == 0 {
					return errReplayFormat
				}
			case 8, 9, 10:
				if v.scalar(f, 's', 63, false) != nil || !operationalDNSLabel(f.value) {
					return errReplayFormat
				}
			case 11, 12, 13:
				if v.scalar(f, 's', 512, false) != nil || !operationalDeploymentPath(f.value) {
					return errReplayFormat
				}
			}
		}
		if string(d[9].value) != "es-operational-v1" {
			return errReplayFormat
		}
		// Looking up the already budgeted leaves here adds no retained data.
		budget := replayDecodeBudget{}
		placement, err := parseReplayObject(fields[6].value, 6, &budget, 2, 2)
		if err != nil || !bytes.Equal(placement[3].value, d[8].value) {
			return errReplayFormat
		}
		for i := 0; i < 3; i++ {
			if !bytes.Equal(placement[i].value, d[10+i].value) {
				return errReplayFormat
			}
		}
		image, err := parseReplayObject(fields[5].value, 5, &budget, 2, 2)
		if err != nil || !operationalNonzeroRef(image[1].value) ||
			!strings.HasSuffix(string(image[0].value), "@sha256:"+fmtHex(image[1].value)) ||
			len(image[2].value) == 0 || !bytes.Equal(image[4].value, d[8].value) {
			return errReplayFormat
		}
		return nil
	})
}

func operationalNonzeroRef(raw []byte) bool {
	if len(raw) != 32 {
		return false
	}
	var anyBits byte
	for _, ch := range raw {
		anyBits |= ch
	}
	return anyBits != 0
}

func validOperationalRun(ref RunRef) bool {
	raw := ref.ref.value
	if len(raw) != 69 || string(raw[:5]) != "esoh-" {
		return false
	}
	nonzero := false
	for _, ch := range raw[5:] {
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
			return false
		}
		nonzero = nonzero || ch != '0'
	}
	return nonzero
}

func (r durableClaimRecord) validateOperationalProgress() error {
	if !r.replay.validForScope(3) || len(r.claim.caller.ref.value) != 32 ||
		len(r.claim.submitKey.ref.value) != 32 || len(r.plan.binding.ref.value) > 256 ||
		!operationalNonzeroRef(r.lastMutation.ref.value) || r.expiresAt.valid ||
		r.retention.state != durableRetentionActive || r.createdAt.UnixNano() <= 0 ||
		!time.Unix(0, r.createdAt.UnixNano()).Equal(r.createdAt) ||
		!time.Unix(0, r.updatedAt.UnixNano()).Equal(r.updatedAt) ||
		r.effects.reconciliation.present() {
		return errInvalidDurableRecord
	}
	for _, ref := range []opaqueRef{r.phase.receipt.ref, r.effects.intent.ref.ref, r.effects.staging.ref.ref,
		r.effects.dispatch.ref.ref, r.effects.provider.fact.ref.ref} {
		if ref.valid() && !operationalNonzeroRef(ref.value) {
			return errInvalidDurableRecord
		}
	}
	if r.revision == 1 {
		if r.phase.tag != durablePhasePendingBeforeAssignment || r.latestOperation.kind != durableOperationEstablishClaim ||
			!r.updatedAt.Equal(r.createdAt) || r.phase.run.Valid() {
			return errInvalidDurableRecord
		}
		return nil
	}
	if r.progressRowID <= 0 || !validOperationalRun(r.phase.run) {
		return errInvalidDurableRecord
	}
	previous := r.createdAt
	missing := false
	for _, at := range []optionalClaimTime{r.assignedAt, r.effects.intent.at, r.effects.staging.at, r.effects.dispatch.at, r.effects.provider.fact.at} {
		if !at.valid {
			missing = true
			continue
		}
		if missing || at.value.Before(previous) || at.value.After(r.updatedAt) ||
			!time.Unix(0, at.value.UnixNano()).Equal(at.value) {
			return errInvalidDurableRecord
		}
		previous = at.value
	}
	if !r.updatedAt.Equal(previous) {
		return errInvalidDurableRecord
	}
	sequence := [...]durableOperationKind{durableOperationAssignRun, durableOperationRecordProviderEffectIntent,
		durableOperationRecordStagingEvidence, durableOperationRecordProviderDispatchAttempt, durableOperationAcceptWithReceipt}
	if r.revision < 2 || r.revision > 6 || r.latestOperation.kind != sequence[r.revision-2] {
		return errInvalidDurableRecord
	}
	wantPresence := []bool{r.assignedAt.valid, r.effects.intent.present(), r.effects.staging.present(),
		r.effects.dispatch.present(), r.effects.provider.present()}
	for i, present := range wantPresence {
		if present != (claimRevision(i)+2 <= r.revision) {
			return errInvalidDurableRecord
		}
	}
	if r.revision == 6 {
		if r.phase.tag != durablePhaseAccepted || r.effects.provider.kind != durableProviderObservationAccepted {
			return errInvalidDurableRecord
		}
	} else if r.phase.tag != durablePhaseEffectCapableAssigned {
		return errInvalidDurableRecord
	}
	return nil
}

func (s *sqliteClaimStore) requireNewOperationalSlot(ctx context.Context, conn *sql.Conn, claim ClaimID) error {
	var occupied int
	err := conn.QueryRowContext(ctx, `SELECT 1 FROM reliable_submit_claims WHERE caller_ref=? AND submit_key_ref=?`,
		claim.caller.ref.value, claim.submitKey.ref.value).Scan(&occupied)
	if err == nil {
		return errOperationalOccupied
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return mapSQLiteError(err)
	}
	count, err := operationalClaimCount(ctx, conn)
	if err != nil {
		return err
	}
	if count >= 4 {
		return errOperationalCapacity
	}
	return nil
}

func operationalClaimCount(ctx context.Context, conn *sql.Conn) (int, error) {
	var count int
	err := conn.QueryRowContext(ctx, `SELECT count(*) FROM reliable_submit_claims WHERE codec_version=5`).Scan(&count)
	return count, mapSQLiteError(err)
}

var (
	errOperationalOccupied = errors.New("operational handoff: occupied")
	errOperationalCapacity = errors.New("operational handoff: capacity")
)

func (s *sqliteClaimStore) requireOperationalKeys(ctx context.Context, conn *sql.Conn, keys PrivateReplayKeys, activeOnly bool) error {
	if !keys.valid {
		return errClaimStoreUnavailable
	}
	for _, key := range []struct {
		id      string
		purpose int
		fp      [32]byte
	}{
		{keys.bindingID, replayKeyPurposeBinding, keys.bindingFP},
		{keys.envelopeID, replayKeyPurposeEnvelope, keys.envelopeFP},
	} {
		if err := s.registerOrCompareReplayKey(ctx, conn, key.id, key.purpose, key.fp, false); err != nil {
			return err
		}
		if activeOnly {
			var state int
			if err := conn.QueryRowContext(ctx, `SELECT state FROM reliable_submit_key_registry WHERE key_id=? COLLATE BINARY`, key.id).Scan(&state); err != nil ||
				state != replayKeyStateActive {
				return errClaimStoreUnavailable
			}
		}
	}
	return nil
}

func randomOperationalMutation() (durableMutationRef, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil || !operationalNonzeroRef(b[:]) {
		return durableMutationRef{}, errClaimStoreUnavailable
	}
	return newDurableMutationRef(b[:])
}

func newOperationalRecord(claim ClaimID, plan BoundPlan, d replayClaimDescriptor, now time.Time, mutation durableMutationRef) (durableClaimRecord, error) {
	if !claim.Valid() || !plan.Valid() || !d.validForScope(3) {
		return durableClaimRecord{}, errInvalidDurableRecord
	}
	resolved, inapplicable, err := sqliteWitnessMasks(plan.Witness())
	if err != nil {
		return durableClaimRecord{}, err
	}
	now = normalizeClaimTime(now)
	wire := append([]byte("ESRSEST2"), claim.caller.ref.value...)
	wire = append(wire, claim.submitKey.ref.value...)
	wire = binary.BigEndian.AppendUint32(wire, uint32(len(plan.binding.ref.value)))
	wire = append(wire, plan.binding.ref.value...)
	wire = binary.BigEndian.AppendUint16(wire, uint16(resolved))
	wire = binary.BigEndian.AppendUint16(wire, uint16(inapplicable))
	wire = append(wire, byte(durablePhasePendingBeforeAssignment))
	wire = binary.BigEndian.AppendUint64(wire, uint64(now.UnixNano()))
	wire = binary.BigEndian.AppendUint16(wire, durableClaimCodecVersionOperational)
	wire = append(wire, byte(d.scope))
	wire = binary.BigEndian.AppendUint16(wire, uint16(d.intentFormat))
	wire = append(wire, d.intentMAC[:]...)
	wire = append(wire, d.contextMAC[:]...)
	wire = binary.BigEndian.AppendUint16(wire, uint16(d.wrapperFormat))
	wire = binary.BigEndian.AppendUint16(wire, uint16(d.payloadFormat))
	wire = binary.BigEndian.AppendUint16(wire, uint16(d.algorithm))
	wire = append(wire, d.ref...)
	wire = binary.BigEndian.AppendUint32(wire, uint32(d.size))
	wire = append(wire, d.fileSHA[:]...)
	wire = binary.BigEndian.AppendUint16(wire, uint16(len(d.bindingKeyID)))
	wire = append(wire, d.bindingKeyID...)
	wire = append(wire, d.bindingKeyFP[:]...)
	wire = binary.BigEndian.AppendUint16(wire, uint16(len(d.envelopeKeyID)))
	wire = append(wire, d.envelopeKeyID...)
	wire = append(wire, d.envelopeKeyFP[:]...)
	op, err := deriveDurableOperationDescriptor(mutation, durableOperationEstablishClaim, 0,
		durableOperationInputPart{tag: durableOperationPartSyntheticDescriptor, value: wire})
	if err != nil {
		return durableClaimRecord{}, err
	}
	r := durableClaimRecord{codecVersion: durableClaimCodecVersionOperational, claim: claim.clone(), plan: plan.clone(),
		phase: durablePhaseSnapshot{tag: durablePhasePendingBeforeAssignment}, revision: initialClaimRevision, replay: d,
		createdAt: now, updatedAt: now, retention: activeDurableRetention(), lastMutation: mutation, latestOperation: op}
	return r, r.validate()
}

func openProvisionedOperationalSQLite(ctx context.Context, path string) (*sqliteClaimStore, error) {
	u, err := url.Parse(sqliteClaimStoreDSN(path, sqliteDefaultBusyTimeoutMS))
	if err != nil {
		return nil, errClaimStoreUnavailable
	}
	query := u.Query()
	query.Set("mode", "rw")
	u.RawQuery = query.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, errClaimStoreUnavailable
	}
	db.SetMaxOpenConns(sqliteDefaultMaxOpenConns)
	s := &sqliteClaimStore{db: db, path: path, dsn: u.String()}
	conn, err := s.checkedConn(ctx)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	err = qualifyOperationalOpening(ctx, conn)
	if releaseErr := conn.Close(); releaseErr != nil || err != nil {
		_ = db.Close()
		if errors.Is(err, errOperationalCapacity) && releaseErr == nil {
			return nil, err
		}
		return nil, errClaimStoreUnavailable
	}
	return s, nil
}

func qualifyOperationalOpening(ctx context.Context, conn *sql.Conn) (out error) {
	if _, err := conn.ExecContext(ctx, "BEGIN"); err != nil {
		return errClaimStoreUnavailable
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := conn.ExecContext(cleanup, "ROLLBACK"); err != nil {
			_ = discardUncertainSQLiteConn(conn)
			out = errClaimStoreUnavailable
		}
	}()
	if err := verifySQLiteStoreCurrent(ctx, conn); err != nil {
		return err
	}
	count, err := operationalClaimCount(ctx, conn)
	if err != nil {
		return err
	}
	if count > 4 {
		return errOperationalCapacity
	}
	return ctx.Err()
}

// OperationalCustody holds its own database and custody anchors. A fixture
// custody value cannot construct it or supply any successful operational fact.
type OperationalCustody struct {
	privateReplayRedacted
	self          *OperationalCustody
	base          *PrivateReplayCustody
	dbFD          int
	db            unix.Stat_t
	mu            sync.RWMutex
	fault         operationalCommitFault
	prestageProof OperationalPrestageProofHooks
	releaseProof  func(OperationalOperation)
}

// OperationalPrestageProofHooks observes only the read-only pre-stage turn. Its
// modeled release response is applied after the real connection close result.
// Configuration is per custody instance and remains nil in ordinary operation.
type OperationalPrestageProofHooks struct {
	AfterSemantic func()
	AfterRollback func(bool) bool
	AfterRelease  func(bool) bool
	Observe       func(OperationalCheck)
}

func (c *OperationalCustody) ConfigureOperationalPrestageProofForProof(proof OperationalPrestageProofHooks) error {
	if c == nil || c.self != c {
		return errClaimStoreUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.base == nil {
		return errClaimStoreUnavailable
	}
	c.prestageProof = proof
	return nil
}

func OpenProvisionedOperationalCustody(ctx context.Context, root string) (*OperationalCustody, error) {
	base, err := openReplayCustody(ctx, root, true)
	if err != nil {
		return nil, err
	}
	fd, err := openReplayReadOnlyCandidate(base.rootFD, "reliable-submit.sqlite3")
	if err != nil {
		_ = base.Close()
		return nil, errClaimStoreUnavailable
	}
	c := &OperationalCustody{base: base, dbFD: fd}
	c.self = c
	if unix.Fstat(fd, &c.db) != nil || c.qualify() != nil {
		_ = c.Close()
		return nil, errClaimStoreUnavailable
	}
	return c, nil
}

func (c *OperationalCustody) qualify() error {
	if c == nil || c.self != c || c.base == nil || c.dbFD < 0 ||
		c.base.checkParents() != nil || c.base.checkFixtureDBBudget() != nil {
		return errClaimStoreUnavailable
	}
	var held, visible unix.Stat_t
	if unix.Fstat(c.dbFD, &held) != nil ||
		unix.Fstatat(c.base.rootFD, "reliable-submit.sqlite3", &visible, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		!replayFileQualified(held) || !replayFileQualified(visible) || !sameReplayIdentity(held, c.db) ||
		!sameReplayIdentity(held, visible) || held.Dev != c.base.rootStat.Dev {
		return errClaimStoreUnavailable
	}
	return nil
}

func (c *OperationalCustody) Close() error {
	if c == nil || c.self != c {
		return errClaimStoreUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.base == nil {
		return nil
	}
	fd, base := c.dbFD, c.base
	c.dbFD, c.base = -1, nil
	c.prestageProof = OperationalPrestageProofHooks{}
	c.releaseProof = nil
	return errors.Join(unix.Close(fd), base.Close())
}

type OperationalDisposition uint8

const (
	OperationalRefused OperationalDisposition = iota
	OperationalAbsent
	OperationalCurrent
	OperationalConflict
	OperationalOccupied
	OperationalStale
	OperationalNoChange
	OperationalExactReplay
	OperationalDefinitelyNotApplied
	OperationalUnknown
	OperationalOwnCommitConfirmed
	OperationalApplied
	OperationalMarkerDirect
	OperationalAppliedReleaseFailed
)

// OperationalReason is a value-free private result classification.
type OperationalReason uint8

const (
	OperationalReasonNone OperationalReason = iota
	OperationalUnavailable
	OperationalCanceled
	OperationalStaleReason
	OperationalWrongScope
	OperationalIntentConflict
	OperationalOccupiedReason
	OperationalClosed
	OperationalIntegrity
	OperationalCapacity
	OperationalUnsupported
	OperationalInconclusive
	OperationalTimeout
	OperationalIO
	OperationalHTTPRefusal
	OperationalMalformed
	OperationalContinuity
	// OperationalDenied means the current admission content refuses this
	// claim. It is distinct from an absent, fenced or stale authority.
	OperationalDenied
)

type OperationalCheck struct {
	disposition OperationalDisposition
	reason      OperationalReason
}

func (c OperationalCheck) Disposition() OperationalDisposition { return c.disposition }
func (c OperationalCheck) Reason() OperationalReason           { return c.reason }

func operationalRefusal(reason OperationalReason) OperationalCheck {
	return OperationalCheck{disposition: OperationalRefused, reason: reason}
}

func operationalFailureReason(ctx context.Context, reason OperationalReason) OperationalReason {
	if ctx.Err() != nil {
		return OperationalCanceled
	}
	return reason
}

func operationalStorageReason(ctx context.Context, err error) OperationalReason {
	if ctx.Err() != nil {
		return OperationalCanceled
	}
	switch {
	case errors.Is(err, errOperationalCapacity):
		return OperationalCapacity
	case errors.Is(err, errClaimStoreCorrupt):
		return OperationalIntegrity
	case errors.Is(err, errClaimStoreUnsupported):
		return OperationalUnsupported
	default:
		return OperationalUnavailable
	}
}

type OperationalProjection struct {
	privateReplayRedacted
	revision    int64
	run         string
	receipt     ReceiptRef
	original    [32]byte
	intent      [32]byte
	stamp       [32]byte
	dispatch    [32]byte
	observation [32]byte
}

func (p OperationalProjection) Revision() int64 { return p.revision }
func (p OperationalProjection) Locator() (stage, job string, ok bool) {
	if p.run == "" {
		return "", "", false
	}
	return p.run, "esoh-job-" + p.run[5:], true
}
func (p OperationalProjection) Receipt() ReceiptRef { return p.receipt.clone() }
func (p OperationalProjection) Bindings() (original, intent, stage, marker, observation [32]byte) {
	return p.original, p.intent, p.stamp, p.dispatch, p.observation
}

func operationalIdentity(record durableClaimRecord, header []byte) ([32]byte, error) {
	resolved, inapplicable, err := sqliteWitnessMasks(record.plan.Witness())
	if record.progressRowID <= 0 || err != nil {
		return [32]byte{}, errClaimStoreUnavailable
	}
	d := record.replay
	buf := binary.BigEndian.AppendUint64([]byte("ESOHORIG1"), uint64(record.progressRowID))
	buf = append(buf, record.claim.caller.ref.value...)
	buf = append(buf, record.claim.submitKey.ref.value...)
	buf = operationalAppendFrame(buf, record.plan.binding.ref.value)
	buf = binary.BigEndian.AppendUint16(buf, uint16(resolved))
	buf = binary.BigEndian.AppendUint16(buf, uint16(inapplicable))
	buf = binary.BigEndian.AppendUint64(buf, uint64(record.createdAt.UnixNano()))
	buf = operationalAppendFrame(buf, header)
	buf = operationalAppendFrame(buf, []byte(d.ref))
	buf = binary.BigEndian.AppendUint64(buf, uint64(d.size))
	buf = append(buf, d.fileSHA[:]...)
	buf = append(buf, d.bindingKeyFP[:]...)
	buf = append(buf, d.envelopeKeyFP[:]...)
	return sha256.Sum256(buf), nil
}

func operationalAppendFrame(buf, value []byte) []byte {
	return append(binary.BigEndian.AppendUint32(buf, uint32(len(value))), value...)
}

func projectOperational(record durableClaimRecord, header []byte) (OperationalProjection, error) {
	identity, err := operationalIdentity(record, header)
	if err != nil {
		return OperationalProjection{}, err
	}
	out := OperationalProjection{revision: int64(record.revision), run: string(record.phase.run.ref.value),
		receipt: record.phase.receipt.clone(), original: identity}
	copy(out.intent[:], record.effects.intent.ref.ref.value)
	copy(out.stamp[:], record.effects.staging.ref.ref.value)
	copy(out.dispatch[:], record.effects.dispatch.ref.ref.value)
	copy(out.observation[:], record.effects.provider.fact.ref.ref.value)
	return out, nil
}

// OperationalOriginalView is a bounded, synchronous view of an authenticated
// scope-3 original. Its typed field projection conveys no write authority.
type OperationalOriginalView struct {
	privateReplayRedacted
	life  *progressOriginalLifetime
	nodes [11]progressOriginalNode
}

func operationalOriginalView(ctx context.Context, raw []byte) (*OperationalOriginalView, error) {
	fields, err := operationalReplayFormat.parsePayload(raw)
	if err != nil {
		return nil, err
	}
	v := &OperationalOriginalView{life: &progressOriginalLifetime{ctx: ctx}}
	for i := range fields {
		fields[i].progressNode = &v.nodes[i]
	}
	if err := validateReplayPayloadStructureForScope(fields, 3); err != nil {
		return nil, err
	}
	return v, nil
}

func (v *OperationalOriginalView) Fields() ([]ProgressOriginalField, error) {
	if v == nil || !v.life.live() {
		return nil, errClaimStoreUnavailable
	}
	return progressFields(v.life, v.nodes[:]), nil
}

type OperationalOriginalMatch struct {
	privateReplayRedacted
	claim     ClaimID
	plan      BoundPlan
	digest    [32]byte
	admission OperationalAdmissionToken
}

func MatchOperationalOriginal(claim ClaimID, plan BoundPlan, encoded []byte) (OperationalOriginalMatch, error) {
	if !claim.Valid() || !plan.Valid() {
		return OperationalOriginalMatch{}, errClaimStoreUnavailable
	}
	if _, err := operationalReplayFormat.parsePayload(encoded); err != nil {
		return OperationalOriginalMatch{}, errClaimStoreUnavailable
	}
	return OperationalOriginalMatch{claim: claim.clone(), plan: plan.clone(), digest: sha256.Sum256(encoded)}, nil
}

// MatchAdmittedOperationalOriginal is the match a first-effect cut requires.
// It carries the admission token the caller holds; the store compares that
// token with the admission row it read for the same cut. A match built by
// MatchOperationalOriginal carries none and can only serve a retained read.
func MatchAdmittedOperationalOriginal(claim ClaimID, plan BoundPlan, encoded []byte,
	admission OperationalAdmissionToken) (OperationalOriginalMatch, error) {
	if !admission.Valid() {
		return OperationalOriginalMatch{}, errClaimStoreUnavailable
	}
	match, err := MatchOperationalOriginal(claim, plan, encoded)
	if err != nil {
		return OperationalOriginalMatch{}, err
	}
	match.admission = admission
	return match, nil
}

// OperationalQualification is the bounded local callback of a first-effect
// cut. It receives the enabled admission token the store read for that cut,
// or the zero token when the domain is uncommissioned or withdrawn, and
// returns an admitted match. The store compares the returned token itself.
type OperationalQualification func(current OperationalAdmissionToken) (OperationalOriginalMatch, error)

type OperationalAccess struct {
	privateReplayRedacted
	self     *OperationalAccess
	issuer   *OperationalCustody
	record   durableClaimRecord
	keys     PrivateReplayKeys
	life     *progressOriginalLifetime
	objectFD int
	object   unix.Stat_t
	header   []byte
	digest   [32]byte
	busy     atomic.Bool
}

type OperationalOriginalRead uint8

const (
	OperationalRetainedRead OperationalOriginalRead = iota + 1
	OperationalEstablishmentRead
)

func (c *OperationalCustody) WithOperationalOriginal(ctx context.Context, claim ClaimID, keys PrivateReplayKeys, exactIntent []byte, read OperationalOriginalRead,
	verify func(*OperationalOriginalView) (OperationalOriginalMatch, error), use func(*OperationalAccess, OperationalProjection)) OperationalCheck {
	if c == nil || c.self != c {
		return operationalRefusal(OperationalClosed)
	}
	if ctx.Err() != nil || verify == nil || use == nil || !claim.Valid() || !keys.valid ||
		len(exactIntent) < 2 || len(exactIntent) > 262144 ||
		(read != OperationalRetainedRead && read != OperationalEstablishmentRead) {
		return operationalRefusal(operationalFailureReason(ctx, OperationalIntegrity))
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.base == nil {
		return operationalRefusal(OperationalClosed)
	}
	if c.qualify() != nil {
		return operationalRefusal(OperationalIntegrity)
	}
	record, err := c.base.store.loadClaim(ctx, loadClaimQuery{claim: claim})
	if errors.Is(err, errClaimStoreNotFound) {
		return OperationalCheck{disposition: OperationalAbsent}
	}
	if err != nil {
		return operationalRefusal(operationalStorageReason(ctx, err))
	}
	if record.codecVersion != durableClaimCodecVersionOperational {
		return operationalRefusal(OperationalWrongScope)
	}
	if !progressKeysMatch(record.replay, keys) || c.base.store.checkOriginalReplayKeys(ctx, keys, read == OperationalEstablishmentRead) != nil {
		return operationalRefusal(operationalFailureReason(ctx, OperationalIntegrity))
	}
	a := &OperationalAccess{issuer: c, keys: keys, record: record,
		life: &progressOriginalLifetime{ctx: ctx}, objectFD: -1}
	a.self = a
	if err := a.openObject(); err != nil {
		return operationalRefusal(operationalFailureReason(ctx, OperationalIntegrity))
	}
	defer func() {
		a.life.closed.Store(true)
		_ = unix.Close(a.objectFD)
	}()
	raw, header, err := a.authenticateObject(ctx)
	if err != nil {
		return operationalRefusal(operationalFailureReason(ctx, OperationalIntegrity))
	}
	a.header = header
	view, err := operationalOriginalView(ctx, raw)
	if err != nil {
		return operationalRefusal(operationalFailureReason(ctx, OperationalIntegrity))
	}
	m, err := verify(view)
	view.life.closed.Store(true)
	a.digest = sha256.Sum256(raw)
	if err != nil || !a.matchesOriginal(m) {
		return operationalRefusal(operationalFailureReason(ctx, OperationalIntegrity))
	}
	p, err := projectOperational(record, header)
	if err != nil || ctx.Err() != nil {
		return operationalRefusal(operationalFailureReason(ctx, OperationalIntegrity))
	}
	intent, err := encodeReplayField(replayField{id: 2, state: 1, value: exactIntent})
	if err != nil {
		return operationalRefusal(OperationalIntegrity)
	}
	wantIntent := replayHMAC(keys.binding, operationalReplayFormat.intentDomain, intent)
	if !hmac.Equal(wantIntent[:], record.replay.intentMAC[:]) {
		return OperationalCheck{disposition: OperationalConflict, reason: OperationalIntentConflict}
	}
	use(a, p)
	return OperationalCheck{disposition: OperationalCurrent}
}

func (a *OperationalAccess) openObject() error {
	fd, err := openReplayReadOnlyCandidate(a.issuer.base.parentFD, a.record.replay.ref[11:])
	if err != nil {
		return errClaimStoreUnavailable
	}
	if unix.Fstat(fd, &a.object) != nil || !replayFileQualified(a.object) || a.object.Size != a.record.replay.size ||
		a.object.Dev != a.issuer.base.parentStat.Dev {
		_ = unix.Close(fd)
		return errClaimStoreUnavailable
	}
	a.objectFD = fd
	return nil
}

func (a *OperationalAccess) authenticateObject(ctx context.Context) ([]byte, []byte, error) {
	if ctx.Err() != nil || !a.life.live() || a.issuer.qualify() != nil {
		return nil, nil, errClaimStoreUnavailable
	}
	if !a.objectVisible() {
		return nil, nil, errClaimStoreUnavailable
	}
	if _, err := unix.Seek(a.objectFD, 0, 0); err != nil {
		return nil, nil, errClaimStoreUnavailable
	}
	raw, err := readReplayFD(a.objectFD, int(a.record.replay.size))
	if err != nil || !a.objectVisible() {
		return nil, nil, errClaimStoreUnavailable
	}
	clear, err := verifyReplayFileBytes(raw, a.record.claim, a.record.plan, a.keys, a.record.replay)
	if err != nil {
		return nil, nil, err
	}
	_, header, err := operationalReplayFormat.parseHeader(raw)
	return clear, bytes.Clone(header), err
}

func (a *OperationalAccess) objectVisible() bool {
	var held, visible unix.Stat_t
	return unix.Fstat(a.objectFD, &held) == nil &&
		unix.Fstatat(a.issuer.base.parentFD, a.record.replay.ref[11:], &visible, unix.AT_SYMLINK_NOFOLLOW) == nil &&
		replayFileQualified(held) && replayFileQualified(visible) && sameReplayIdentity(held, visible) &&
		sameReplayIdentity(held, a.object) && held.Size == a.record.replay.size && visible.Size == held.Size
}

type OperationalOperation uint8

const (
	OperationalEstablish OperationalOperation = 1
	OperationalAssign    OperationalOperation = 2
	OperationalIntent    OperationalOperation = 3
	OperationalStamp     OperationalOperation = 4
	OperationalMark      OperationalOperation = 5
	OperationalAccept    OperationalOperation = 8
)

type operationalCommitFault struct {
	op        OperationalOperation
	rollback  bool
	replyLost func()
}

// ConfigureOperationalCommitFaultForProof selects a single real transaction
// outcome witness. It can withhold an acknowledgement or roll back; it cannot
// substitute successful communication with SQLite.
func (c *OperationalCustody) ConfigureOperationalCommitFaultForProof(op OperationalOperation, rollback bool, afterAcknowledgedCommit ...func()) error {
	if c == nil || c.self != c || len(afterAcknowledgedCommit) > 1 || rollback && len(afterAcknowledgedCommit) != 0 {
		return errClaimStoreUnavailable
	}
	switch op {
	case OperationalEstablish, OperationalAssign, OperationalIntent, OperationalStamp, OperationalMark, OperationalAccept:
	default:
		return errClaimStoreUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.base == nil {
		return errClaimStoreUnavailable
	}
	c.fault = operationalCommitFault{op: op, rollback: rollback}
	if len(afterAcknowledgedCommit) == 1 {
		c.fault.replyLost = afterAcknowledgedCommit[0]
	}
	return nil
}

type operationalTurnResult struct {
	record durableClaimRecord
	kind   OperationalDisposition
	reason OperationalReason
}

func (r operationalTurnResult) check(ctx context.Context) OperationalCheck {
	reason := r.reason
	switch r.kind {
	case OperationalStale:
		reason = OperationalStaleReason
	case OperationalRefused, OperationalUnknown, OperationalAppliedReleaseFailed:
		if reason == OperationalReasonNone {
			reason = operationalFailureReason(ctx, OperationalUnavailable)
		}
	}
	return OperationalCheck{disposition: r.kind, reason: reason}
}

// operationalTurn owns the writer and its response classification. The
// complete expected row is saved before COMMIT. Readback has no path to the
// directly applied marker result.
func (c *OperationalCustody) operationalTurn(ctx context.Context, op OperationalOperation, step func(*sql.Conn) operationalTurnResult) operationalTurnResult {
	if ctx.Err() != nil || c.qualify() != nil {
		return operationalTurnResult{kind: OperationalRefused}
	}
	s := c.base.store
	conn, err := s.checkedConn(ctx)
	if err != nil {
		return operationalTurnResult{kind: OperationalRefused}
	}
	release := true
	defer func() {
		if release {
			_ = conn.Close()
		}
	}()
	discard := func() bool {
		release = false
		if discardUncertainSQLiteConn(conn) == nil || discardUncertainSQLiteConn(conn) == nil {
			release = true
		}
		return release
	}
	if err := beginImmediate(ctx, conn); err != nil {
		discard()
		return operationalTurnResult{kind: OperationalRefused}
	}
	rollback := func() bool {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := conn.ExecContext(cleanup, "ROLLBACK")
		timely := cleanup.Err() == nil
		cancel()
		if err != nil || !timely {
			discard()
			return false
		}
		return true
	}
	if c.qualify() != nil || verifySQLiteStoreCurrent(ctx, conn) != nil {
		rollback()
		return operationalTurnResult{kind: OperationalRefused}
	}
	result := step(conn)
	if op == 0 && result.kind == OperationalNoChange && c.prestageProof.AfterSemantic != nil {
		c.prestageProof.AfterSemantic()
	}
	if result.kind != OperationalApplied {
		if op == 0 && result.kind == OperationalNoChange &&
			(c.prestageProof.AfterRollback != nil || c.prestageProof.AfterRelease != nil) {
			rolledBack := rollback()
			modeledRollbackFailure := false
			if c.prestageProof.AfterRollback != nil {
				modeledRollbackFailure = c.prestageProof.AfterRollback(rolledBack)
			}
			if !rolledBack || modeledRollbackFailure {
				return operationalTurnResult{kind: result.kind, reason: operationalFailureReason(ctx, OperationalClosed)}
			}
			closeErr := conn.Close()
			modeledFailure := false
			if c.prestageProof.AfterRelease != nil {
				modeledFailure = c.prestageProof.AfterRelease(closeErr == nil)
			}
			if closeErr != nil || modeledFailure || ctx.Err() != nil {
				return operationalTurnResult{kind: result.kind, reason: operationalFailureReason(ctx, OperationalClosed)}
			}
			release = false
			return result
		}
		if !rollback() || conn.Close() != nil || ctx.Err() != nil {
			return operationalTurnResult{kind: result.kind, reason: operationalFailureReason(ctx, OperationalClosed)}
		}
		release = false
		return result
	}
	if ctx.Err() != nil || c.fault.op == op && c.fault.rollback {
		if rollback() {
			return operationalTurnResult{kind: OperationalDefinitelyNotApplied}
		}
		return operationalTurnResult{kind: OperationalUnknown}
	}
	if err := commit(ctx, conn); err != nil || c.fault.op == op {
		if err == nil && c.fault.replyLost != nil {
			c.fault.replyLost()
		}
		kind := OperationalUnknown
		if discard() && ctx.Err() == nil && c.qualify() == nil {
			observation, err := s.loadClaim(ctx, loadClaimQuery{claim: result.record.claim})
			if err == nil && observation.equal(result.record) {
				kind = OperationalOwnCommitConfirmed
			}
		}
		result.kind = kind
		return result
	}
	if err := conn.Close(); err != nil || ctx.Err() != nil || c.qualify() != nil {
		discard()
		return operationalTurnResult{kind: OperationalAppliedReleaseFailed}
	}
	release = false
	if op == OperationalMark {
		result.kind = OperationalMarkerDirect
	}
	return result
}

func (c *OperationalCustody) EstablishOperational(ctx context.Context, claim ClaimID, plan BoundPlan, keys PrivateReplayKeys, raw []byte,
	admission OperationalAdmissionToken) OperationalCheck {
	if c == nil || c.self != c {
		return operationalRefusal(OperationalClosed)
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.base == nil {
		return operationalRefusal(OperationalClosed)
	}
	if ctx.Err() != nil || c.qualify() != nil {
		return operationalRefusal(operationalFailureReason(ctx, OperationalIntegrity))
	}
	frozen, err := freezeReplayOriginal(operationalReplayFormat, claim, plan, keys, raw)
	if err != nil {
		return operationalRefusal(operationalFailureReason(ctx, OperationalIntegrity))
	}
	s := c.base.store
	// A hint only: it keeps a process that does not know it is fenced from
	// charging a nonrefundable reservation. The turn below is the authority.
	if hint, ok := s.pooledOperationalAdmission(ctx); !ok || !admission.Valid() || hint != admission {
		return operationalRefusal(operationalFailureReason(ctx, OperationalUnavailable))
	}
	permit, err := s.reserveReplaySealUseWithScope(ctx, keys, frozen.digest, false, &frozen)
	if errors.Is(err, errOperationalOccupied) {
		return OperationalCheck{disposition: OperationalOccupied, reason: OperationalOccupiedReason}
	}
	if err != nil {
		return operationalRefusal(operationalStorageReason(ctx, err))
	}
	pub, err := c.base.publishReplayOriginal(ctx, frozen, PrivateReplaySealPermit{permit: permit})
	if err != nil || !pub.descriptor.validForScope(3) {
		return operationalRefusal(operationalFailureReason(ctx, OperationalIntegrity))
	}
	mutation, err := randomOperationalMutation()
	if err != nil {
		return operationalRefusal(operationalFailureReason(ctx, OperationalIntegrity))
	}
	r, err := newOperationalRecord(claim, plan, pub.descriptor, time.Now(), mutation)
	if err != nil {
		return operationalRefusal(operationalFailureReason(ctx, OperationalIntegrity))
	}
	result := c.operationalTurn(ctx, OperationalEstablish, func(conn *sql.Conn) operationalTurnResult {
		err := s.requireNewOperationalSlot(ctx, conn, claim)
		if errors.Is(err, errOperationalOccupied) {
			return operationalTurnResult{kind: OperationalOccupied, reason: OperationalOccupiedReason}
		}
		if err != nil {
			return operationalTurnResult{kind: OperationalRefused, reason: operationalStorageReason(ctx, err)}
		}
		if current, ok := operationalAdmissionForTurn(ctx, conn); !ok || !admission.Valid() || current != admission {
			return operationalTurnResult{kind: OperationalRefused, reason: operationalFailureReason(ctx, OperationalUnavailable)}
		}
		if s.requireOperationalKeys(ctx, conn, keys, true) != nil {
			return operationalTurnResult{kind: OperationalRefused, reason: operationalFailureReason(ctx, OperationalIntegrity)}
		}
		if original, err := c.base.checkPublishedRef(ctx, claim, plan, keys, r.replay); err != nil || !hmac.Equal(original, raw) {
			return operationalTurnResult{kind: OperationalRefused}
		}
		args, err := sqliteRecordArgs(r)
		if err != nil {
			return operationalTurnResult{kind: OperationalRefused}
		}
		res, err := conn.ExecContext(ctx, sqliteInsertReplayClaimSQL, args...)
		if err != nil {
			return operationalTurnResult{kind: OperationalRefused}
		}
		id, err := res.LastInsertId()
		if id <= 0 || err != nil {
			return operationalTurnResult{kind: OperationalRefused}
		}
		r.progressRowID = id
		written, err := s.selectSQLiteClaim(ctx, conn, r.claim)
		if err != nil || !written.equal(r) {
			return operationalTurnResult{kind: OperationalRefused}
		}
		return operationalTurnResult{kind: OperationalApplied, record: written}
	})
	if result.kind != OperationalApplied && result.kind != OperationalOwnCommitConfirmed {
		return result.check(ctx)
	}
	data, err := c.base.checkPublishedRef(ctx, claim, plan, keys, result.record.replay)
	if err != nil || !hmac.Equal(data, raw) || s.checkOriginalReplayKeys(ctx, keys, true) != nil ||
		c.qualify() != nil || ctx.Err() != nil {
		if result.kind == OperationalOwnCommitConfirmed {
			return OperationalCheck{disposition: OperationalUnknown, reason: operationalFailureReason(ctx, OperationalIntegrity)}
		}
		return OperationalCheck{disposition: OperationalAppliedReleaseFailed, reason: operationalFailureReason(ctx, OperationalIntegrity)}
	}
	return result.check(ctx)
}

func (a *OperationalAccess) currentForTurn(ctx context.Context, conn *sql.Conn, rev int64, active bool) (durableClaimRecord, OperationalDisposition) {
	s := a.issuer.base.store
	r, err := s.selectSQLiteClaim(ctx, conn, a.record.claim)
	if err != nil || r.codecVersion != durableClaimCodecVersionOperational || r.progressRowID != a.record.progressRowID ||
		!r.replay.equal(a.record.replay) || !r.claim.Equal(a.record.claim) || !r.createdAt.Equal(a.record.createdAt) ||
		!r.plan.EqualBinding(a.record.plan.Binding()) || !witnessEqual(r.plan.Witness(), a.record.plan.Witness()) ||
		!progressKeysMatch(r.replay, a.keys) || s.requireOperationalKeys(ctx, conn, a.keys, active) != nil {
		return durableClaimRecord{}, OperationalRefused
	}
	if _, header, err := a.authenticateObject(ctx); err != nil || !hmac.Equal(header, a.header) {
		return durableClaimRecord{}, OperationalRefused
	}
	if int64(r.revision) != rev {
		return r, OperationalStale
	}
	if !r.equal(a.record) {
		return durableClaimRecord{}, OperationalRefused
	}
	return r, OperationalCurrent
}

type OperationalMutation struct {
	privateReplayRedacted
	value durableMutationRef
}

func NewOperationalMutation() (OperationalMutation, error) {
	value, err := randomOperationalMutation()
	return OperationalMutation{value: value}, err
}

type OperationalCommand interface {
	operationalCommand()
}
type AssignOperationalRun struct {
	privateReplayRedacted
	run RunRef
}

func NewAssignOperationalRun() (AssignOperationalRun, error) {
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil || random == [32]byte{} {
		return AssignOperationalRun{}, errClaimStoreUnavailable
	}
	run, err := NewRunRef([]byte("esoh-" + fmtHex(random[:])))
	return AssignOperationalRun{run: run}, err
}

func (AssignOperationalRun) operationalCommand() {}

type OperationalIntentInput struct {
	privateReplayRedacted
	self       *OperationalIntentInput
	access     *OperationalAccess
	projection OperationalProjection
	ref        [32]byte
}

func (*OperationalIntentInput) operationalCommand() {}

func operationalIntentRef(p OperationalProjection, locator [32]byte) [32]byte {
	input := append([]byte("ESOHINT1"), p.original[:]...)
	input = operationalAppendFrame(input, []byte(p.run))
	return sha256.Sum256(append(input, locator[:]...))
}

func (a *OperationalAccess) BindOperationalIntent(p OperationalProjection, locator [32]byte) (*OperationalIntentInput, error) {
	if !a.canBind(p, 2) || locator == [32]byte{} {
		return nil, errClaimStoreUnavailable
	}
	input := &OperationalIntentInput{access: a, projection: p, ref: operationalIntentRef(p, locator)}
	input.self = input
	return input, nil
}

type OperationalStageProof struct {
	privateReplayRedacted
	self       *OperationalStageProof
	access     *OperationalAccess
	projection OperationalProjection
	project    [32]byte
	locator    [32]byte
	ref        [32]byte
	preimage   []byte
	measure    func() ([]byte, error)
}

func (*OperationalStageProof) operationalCommand() {}

func (a *OperationalAccess) BindOperationalStage(p OperationalProjection, project, locator [32]byte, first []byte,
	measure func() ([]byte, error)) (*OperationalStageProof, error) {
	if !a.canBind(p, 3) || project == [32]byte{} || locator == [32]byte{} ||
		p.intent != operationalIntentRef(p, locator) || measure == nil || !validOperationalStagePreimage(p, project, first) {
		return nil, errClaimStoreUnavailable
	}
	stage := &OperationalStageProof{access: a, projection: p, project: project, locator: locator,
		ref: sha256.Sum256(first), preimage: bytes.Clone(first), measure: measure}
	stage.self = stage
	return stage, nil
}

func validOperationalStagePreimage(p OperationalProjection, project [32]byte, raw []byte) bool {
	prefix := operationalAppendFrame(append([]byte("ESOHSTG1"), p.original[:]...), []byte(p.run))
	prefix = append(prefix, p.intent[:]...)
	prefix = append(prefix, project[:]...)
	const identitySize = 37
	if len(raw) < len(prefix)+2*identitySize+2 || len(raw) > 2048 || !bytes.HasPrefix(raw, prefix) {
		return false
	}
	raw = raw[len(prefix):]
	parent := raw[:identitySize]
	root := raw[identitySize : 2*identitySize]
	inodes := make(map[uint64]bool, 10)
	matchesIdentity := func(identity []byte, tag byte, mode uint32) bool {
		inode := binary.BigEndian.Uint64(identity[9:17])
		links := binary.BigEndian.Uint64(identity[29:37])
		valid := identity[0] == tag && bytes.Equal(identity[1:9], parent[1:9]) &&
			inode != 0 && !inodes[inode] && bytes.Equal(identity[17:25], parent[17:25]) &&
			binary.BigEndian.Uint32(identity[25:29]) == mode && links > 0 && (tag != 2 || links == 1)
		inodes[inode] = true
		return valid
	}
	mode := binary.BigEndian.Uint32(parent[25:29])
	if mode > 0o7777 || mode&0o022 != 0 || !matchesIdentity(parent, 1, mode) || !matchesIdentity(root, 1, 0o750) {
		return false
	}
	count := binary.BigEndian.Uint16(raw[2*identitySize:])
	raw = raw[2*identitySize+2:]
	type child struct {
		name string
		tag  byte
		mode uint32
	}
	layout := []child{
		{"payload", 1, 0o750}, {"payload/artifact.tar.gz", 2, 0o600},
		{"run", 1, 0o750}, {"run/platform", 1, 0o750}, {"run/platform/es-runtime-support", 2, 0o750},
	}
	switch count {
	case 6:
	case 8:
		layout = append(layout, child{"run/platform/workload-ca-bundle.pem", 2, 0o640}, child{"run/platform/workload-vault-ca.pem", 2, 0o640})
	default:
		return false
	}
	layout = append(layout, child{"run/result", 1, 0o750})
	var total uint64
	for _, entry := range layout {
		name := operationalAppendFrame(nil, []byte(entry.name))
		size := len(name) + identitySize + 8 + 32
		if len(raw) < size || !bytes.HasPrefix(raw, name) || !matchesIdentity(raw[len(name):], entry.tag, entry.mode) {
			return false
		}
		length := binary.BigEndian.Uint64(raw[size-40:])
		var zero [32]byte
		isZeroDigest := bytes.Equal(raw[size-32:size], zero[:])
		if length > 262144 || entry.tag == 1 && (length != 0 || !isZeroDigest) || entry.tag == 2 && isZeroDigest {
			return false
		}
		total += length
		raw = raw[size:]
	}
	return len(raw) == 0 && total <= 1048576
}

func (s *OperationalStageProof) Requalify() bool {
	if s == nil || s.self != s || !s.access.life.live() || s.measure == nil {
		return false
	}
	now, err := s.measure()
	return err == nil && bytes.Equal(now, s.preimage)
}

type OperationalMarkerCandidate struct {
	privateReplayRedacted
	self       *OperationalMarkerCandidate
	stage      *OperationalStageProof
	projection OperationalProjection
	mutation   [32]byte
	ref        [32]byte
}

func (*OperationalMarkerCandidate) operationalCommand() {}

func (a *OperationalAccess) BindOperationalMarker(p OperationalProjection, m OperationalMutation, stage *OperationalStageProof) (*OperationalMarkerCandidate, error) {
	if !a.canBind(p, 4) || !operationalNonzeroRef(m.value.ref.value) || stage == nil || stage.self != stage ||
		stage.access != a || stage.projection.original != p.original || stage.projection.run != p.run ||
		stage.projection.intent != p.intent || stage.ref != p.stamp || !stage.Requalify() {
		return nil, errClaimStoreUnavailable
	}
	input := operationalAppendFrame(append([]byte("ESOHMRK1"), p.original[:]...), []byte(p.run))
	for _, field := range [][32]byte{p.intent, p.stamp, stage.project, stage.locator} {
		input = append(input, field[:]...)
	}
	input = append(input, m.value.ref.value...)
	marker := &OperationalMarkerCandidate{stage: stage, projection: p, ref: sha256.Sum256(binary.BigEndian.AppendUint64(input, uint64(p.revision)))}
	copy(marker.mutation[:], m.value.ref.value)
	marker.self = marker
	return marker, nil
}

func (m *OperationalMarkerCandidate) Ref() [32]byte {
	if m == nil || m.self != m || !m.stage.access.life.live() {
		return [32]byte{}
	}
	return m.ref
}

func (a *OperationalAccess) canBind(p OperationalProjection, revision int64) bool {
	if a == nil || a.self != a || !a.life.live() || !a.busy.CompareAndSwap(false, true) {
		return false
	}
	defer a.busy.Store(false)
	actual, err := projectOperational(a.record, a.header)
	return err == nil && p.revision == revision && operationalProjectionEqual(actual, p)
}

func (a *OperationalAccess) matchesOriginal(m OperationalOriginalMatch) bool {
	return m.claim.Equal(a.record.claim) && m.plan.EqualBinding(a.record.plan.Binding()) &&
		witnessEqual(m.plan.Witness(), a.record.plan.Witness()) && hmac.Equal(m.digest[:], a.digest[:])
}

// qualifiesOriginal is the fence of a first-effect cut. current is the
// enabled admission token read for this cut. The callback evaluates the
// retained original locally and returns the token its process holds; the
// store requires that token to equal the row.
func (a *OperationalAccess) qualifiesOriginal(current OperationalAdmissionToken, qualify OperationalQualification) bool {
	if qualify == nil {
		return false
	}
	match, err := qualify(current)
	return err == nil && a.matchesOriginal(match) && current.Valid() && match.admission == current
}

// OperationalPositiveProof is scoped to the active original and exact marker.
type OperationalPositiveProof struct {
	privateReplayRedacted
	self        *OperationalPositiveProof
	access      *OperationalAccess
	projection  OperationalProjection
	receipt     ReceiptRef
	observation durableFactRef
}

func (*OperationalPositiveProof) operationalCommand() {}

func (a *OperationalAccess) BindVerifiedOperationalObservation(p OperationalProjection, project, realm [32]byte,
	preimage []byte, witness [32]byte) (*OperationalPositiveProof, error) {
	if a == nil || a.self != a || !a.life.live() || p.revision != 5 || !a.busy.CompareAndSwap(false, true) {
		return nil, errClaimStoreUnavailable
	}
	defer a.busy.Store(false)
	actual, err := projectOperational(a.record, a.header)
	if err != nil || !operationalProjectionEqual(actual, p) || project == [32]byte{} || realm == [32]byte{} || p.intent != operationalIntentRef(p, realm) {
		return nil, errClaimStoreUnavailable
	}
	buf := a.evidenceInput(p, project, realm)
	if len(preimage) != len(buf)+24 || !hmac.Equal(preimage[:len(buf)], buf) ||
		binary.BigEndian.Uint64(preimage[len(buf):]) == 0 || bytes.Equal(preimage[len(buf)+8:], make([]byte, 16)) {
		return nil, errClaimStoreUnavailable
	}
	expectedWitness := replayHMAC(a.keys.binding, "ESOHEVD1", preimage)
	if !hmac.Equal(expectedWitness[:], witness[:]) {
		return nil, errClaimStoreUnavailable
	}
	r := replayHMAC(a.keys.binding, "ESOHREC1", append(buf, witness[:]...))
	receipt, err := NewReceiptRef(r[:])
	if err != nil {
		return nil, errClaimStoreUnavailable
	}
	fact, err := newDurableFactRef(witness[:])
	if err != nil {
		return nil, err
	}
	proof := &OperationalPositiveProof{access: a, projection: actual, receipt: receipt, observation: fact}
	proof.self = proof
	return proof, nil
}

func (a *OperationalAccess) VerifyOperationalReceipt(p OperationalProjection, project, realm [32]byte) bool {
	if a == nil || a.self != a || !a.life.live() || p.revision != 6 || !p.receipt.Valid() || !a.busy.CompareAndSwap(false, true) {
		return false
	}
	defer a.busy.Store(false)
	actual, err := projectOperational(a.record, a.header)
	if err != nil || !operationalProjectionEqual(actual, p) {
		return false
	}
	r := replayHMAC(a.keys.binding, "ESOHREC1", append(a.evidenceInput(p, project, realm), p.observation[:]...))
	return hmac.Equal(r[:], p.receipt.ref.value)
}

func operationalProjectionEqual(a, b OperationalProjection) bool {
	return a.revision == b.revision && a.run == b.run &&
		hmac.Equal(a.original[:], b.original[:]) && hmac.Equal(a.intent[:], b.intent[:]) &&
		hmac.Equal(a.stamp[:], b.stamp[:]) && hmac.Equal(a.dispatch[:], b.dispatch[:]) &&
		hmac.Equal(a.observation[:], b.observation[:]) && hmac.Equal(a.receipt.ref.value, b.receipt.ref.value)
}

func (a *OperationalAccess) evidenceInput(p OperationalProjection, project, realm [32]byte) []byte {
	buf := operationalAppendFrame(bytes.Clone(p.original[:]), []byte(p.run))
	buf = append(buf, p.stamp[:]...)
	buf = append(buf, p.dispatch[:]...)
	buf = append(buf, project[:]...)
	return append(buf, realm[:]...)
}

func (a *OperationalAccess) Prestage(ctx context.Context, projection OperationalProjection, qualify OperationalQualification) OperationalCheck {
	if a == nil || a.self != a || !a.life.live() || qualify == nil || !a.busy.CompareAndSwap(false, true) {
		return operationalRefusal(operationalFailureReason(ctx, OperationalClosed))
	}
	defer a.busy.Store(false)
	result := a.issuer.operationalTurn(ctx, 0, func(conn *sql.Conn) operationalTurnResult {
		r, k := a.currentForTurn(ctx, conn, projection.revision, true)
		if k != OperationalCurrent {
			return operationalTurnResult{kind: k, reason: operationalFailureReason(ctx, OperationalIntegrity)}
		}
		p, err := projectOperational(r, a.header)
		if err != nil || !operationalProjectionEqual(p, projection) || r.revision != 3 {
			return operationalTurnResult{kind: OperationalRefused, reason: operationalFailureReason(ctx, OperationalIntegrity)}
		}
		current, ok := operationalAdmissionForTurn(ctx, conn)
		if !ok || !a.qualifiesOriginal(current, qualify) {
			return operationalTurnResult{kind: OperationalRefused, reason: operationalFailureReason(ctx, OperationalIntegrity)}
		}
		return operationalTurnResult{kind: OperationalNoChange}
	})
	check := result.check(ctx)
	if a.issuer.prestageProof.Observe != nil {
		a.issuer.prestageProof.Observe(check)
	}
	return check
}

func (a *OperationalAccess) Apply(ctx context.Context, p OperationalProjection, m OperationalMutation,
	cmd OperationalCommand, qualify OperationalQualification) (OperationalDisposition, OperationalProjection) {
	return a.applyOperational(ctx, p, m, cmd, qualify, nil)
}

func (a *OperationalAccess) ApplyFirstMarker(ctx context.Context, p OperationalProjection, m OperationalMutation, marker *OperationalMarkerCandidate,
	qualify OperationalQualification, onApplied func(OperationalProjection)) (OperationalDisposition, OperationalProjection) {
	if marker == nil || onApplied == nil {
		return OperationalRefused, OperationalProjection{}
	}
	return a.applyOperational(ctx, p, m, marker, qualify, onApplied)
}

func (a *OperationalAccess) applyOperational(ctx context.Context, p OperationalProjection, m OperationalMutation,
	cmd OperationalCommand, qualify OperationalQualification, onApplied func(OperationalProjection)) (OperationalDisposition, OperationalProjection) {
	if a == nil || a.self != a || !a.life.live() || !operationalNonzeroRef(m.value.ref.value) || !a.busy.CompareAndSwap(false, true) {
		return OperationalRefused, OperationalProjection{}
	}
	defer a.busy.Store(false)
	shape, err := a.operationalCommandShape(p, m, cmd)
	if err != nil || shape.op == OperationalMark && onApplied == nil {
		return OperationalRefused, OperationalProjection{}
	}
	latest, err := deriveDurableOperationDescriptor(m.value, durableOperationKind(shape.op), claimRevision(p.revision), shape.parts...)
	if err != nil {
		return OperationalRefused, OperationalProjection{}
	}
	result := a.issuer.operationalTurn(ctx, shape.op, func(conn *sql.Conn) operationalTurnResult {
		r, k := a.currentForTurn(ctx, conn, p.revision, shape.op != OperationalAccept)
		if k == OperationalStale {
			switch compareDurableLatestOperation(r.latestOperation, latest) {
			case durableOperationReplayExact:
				return operationalTurnResult{kind: OperationalExactReplay, record: r}
			case durableOperationReplayConflict:
				return operationalTurnResult{kind: OperationalConflict}
			}
		}
		if k != OperationalCurrent {
			return operationalTurnResult{kind: k, record: r}
		}
		actual, err := projectOperational(r, a.header)
		if err != nil || !operationalProjectionEqual(actual, p) {
			return operationalTurnResult{kind: OperationalRefused}
		}
		if shape.op != OperationalAccept {
			// Every first-effect writer compares the presented admission token
			// with the row read through this turn's connection. Accept with
			// receipt records a positive fact and is not an admission cut.
			current, ok := operationalAdmissionForTurn(ctx, conn)
			if !ok || !a.qualifiesOriginal(current, qualify) {
				return operationalTurnResult{kind: OperationalRefused}
			}
		}
		if shape.stage != nil && !shape.stage.Requalify() {
			return operationalTurnResult{kind: OperationalRefused}
		}
		at := normalizeClaimTime(time.Now())
		if r.updatedAt.After(at) {
			at = r.updatedAt
		}
		phase, facts, assigned, err := shape.transition(r, at)
		if err != nil {
			return operationalTurnResult{kind: OperationalRefused}
		}
		next, err := r.withPhaseAndOperation(phase, latest, at, assigned, facts, r.retention)
		if err != nil {
			return operationalTurnResult{kind: OperationalRefused}
		}
		written, err := a.issuer.base.store.updateOperationalRow(ctx, conn, r, next)
		if err != nil {
			return operationalTurnResult{kind: OperationalRefused}
		}
		return operationalTurnResult{kind: OperationalApplied, record: written}
	})
	switch result.kind {
	case OperationalExactReplay, OperationalStale:
		if result.reason != OperationalReasonNone || !a.operationalReleaseQualified(ctx, shape.op, qualify, nil) {
			return result.kind, OperationalProjection{}
		}
		project, err := projectOperational(result.record, a.header)
		if err != nil {
			return result.kind, OperationalProjection{}
		}
		a.record = result.record
		return result.kind, project
	case OperationalDefinitelyNotApplied:
		row, err := a.issuer.base.store.loadClaim(ctx, loadClaimQuery{claim: a.record.claim})
		if err == nil && row.equal(a.record) && a.operationalReleaseQualified(ctx, shape.op, qualify, shape.stage) {
			projection, err := projectOperational(row, a.header)
			if err == nil {
				return result.kind, projection
			}
		}
		return result.kind, OperationalProjection{}
	case OperationalApplied, OperationalMarkerDirect, OperationalOwnCommitConfirmed:
		if result.kind != OperationalOwnCommitConfirmed && a.issuer.releaseProof != nil {
			a.issuer.releaseProof(shape.op)
		}
		if !a.operationalReleaseQualified(ctx, shape.op, qualify, shape.stage) {
			if result.kind == OperationalOwnCommitConfirmed {
				return OperationalUnknown, OperationalProjection{}
			}
			return OperationalAppliedReleaseFailed, OperationalProjection{}
		}
		out, err := projectOperational(result.record, a.header)
		if err != nil {
			return OperationalAppliedReleaseFailed, OperationalProjection{}
		}
		a.record = result.record
		if result.kind == OperationalMarkerDirect {
			if onApplied == nil || shape.stage == nil || ctx.Err() != nil {
				return OperationalAppliedReleaseFailed, OperationalProjection{}
			}
			onApplied(out)
		}
		return result.kind, out
	default:
		return result.kind, OperationalProjection{}
	}
}

func (a *OperationalAccess) operationalReleaseQualified(ctx context.Context, op OperationalOperation,
	qualify OperationalQualification, stage *OperationalStageProof) bool {
	if ctx.Err() != nil || a.issuer.qualify() != nil ||
		a.issuer.base.store.checkOriginalReplayKeys(ctx, a.keys, op != OperationalAccept) != nil {
		return false
	}
	_, header, err := a.authenticateObject(ctx)
	if err != nil || !hmac.Equal(header, a.header) {
		return false
	}
	if op != OperationalAccept {
		// The admission row is read again beside the key state: an advance or a
		// withdrawal committed after this write's COMMIT releases nothing.
		current, ok := a.issuer.base.store.pooledOperationalAdmission(ctx)
		if !ok || !a.qualifiesOriginal(current, qualify) {
			return false
		}
	}
	return (stage == nil || stage.Requalify()) && ctx.Err() == nil
}

type operationalStepShape struct {
	op         OperationalOperation
	parts      []durableOperationInputPart
	stage      *OperationalStageProof
	transition func(durableClaimRecord, time.Time) (ClaimPhase, durableEffectFacts, optionalClaimTime, error)
}

func (a *OperationalAccess) operationalCommandShape(p OperationalProjection, m OperationalMutation, command OperationalCommand) (operationalStepShape, error) {
	shape := operationalStepShape{}
	switch cmd := command.(type) {
	case AssignOperationalRun:
		run := cmd.run
		if !validOperationalRun(run) {
			return shape, errInvalidDurableRecord
		}
		shape.op = OperationalAssign
		shape.parts = []durableOperationInputPart{operationPartRunRef(run)}
		shape.transition = func(r durableClaimRecord, at time.Time) (ClaimPhase, durableEffectFacts, optionalClaimTime, error) {
			if r.revision != 1 || r.phase.run.Valid() {
				return nil, durableEffectFacts{}, noClaimTime(), errInvalidDurableRecord
			}
			phase, err := hydrateAssignedPhase(r.claim, r.plan, run)
			return phase, r.effects, someClaimTime(at), err
		}
	case *OperationalIntentInput:
		if cmd == nil || cmd.self != cmd || cmd.access != a || !operationalProjectionEqual(p, cmd.projection) {
			return shape, errClaimStoreUnavailable
		}
		return operationalFactStep(OperationalIntent, cmd.ref, nil)
	case *OperationalStageProof:
		if cmd == nil || cmd.self != cmd || cmd.access != a || !operationalProjectionEqual(p, cmd.projection) {
			return shape, errClaimStoreUnavailable
		}
		return operationalFactStep(OperationalStamp, cmd.ref, cmd)
	case *OperationalMarkerCandidate:
		if cmd == nil || cmd.self != cmd || cmd.stage.access != a || !operationalProjectionEqual(p, cmd.projection) ||
			!hmac.Equal(cmd.mutation[:], m.value.ref.value) {
			return shape, errClaimStoreUnavailable
		}
		return operationalFactStep(OperationalMark, cmd.ref, cmd.stage)
	case *OperationalPositiveProof:
		proof := cmd
		if proof == nil || proof.self != proof || proof.access != a || !operationalProjectionEqual(p, proof.projection) ||
			!proof.receipt.Valid() || !proof.observation.valid() {
			return shape, errClaimStoreUnavailable
		}
		shape.op = OperationalAccept
		shape.parts = []durableOperationInputPart{operationPartReceiptRef(proof.receipt), operationPartFactRef(proof.observation)}
		shape.transition = func(r durableClaimRecord, at time.Time) (ClaimPhase, durableEffectFacts, optionalClaimTime, error) {
			actual, err := projectOperational(r, a.header)
			if err != nil || !operationalProjectionEqual(actual, proof.projection) || r.revision != 5 {
				return nil, durableEffectFacts{}, noClaimTime(), errInvalidDurableRecord
			}
			phase, err := r.hydratePhase()
			candidate, ok := phase.(ProviderOutcomeCandidatePhase)
			if err != nil || !ok {
				return nil, durableEffectFacts{}, noClaimTime(), errInvalidDurableRecord
			}
			accepted, err := NewAccepted(candidate, proof.receipt)
			facts := r.effects.clone()
			facts.provider = durableProviderObservation{kind: durableProviderObservationAccepted, fact: newDurableEffectRefTime(proof.observation, at)}
			return accepted, facts, r.assignedAt, err
		}
	default:
		return shape, errClaimStoreUnavailable
	}
	return shape, nil
}

func operationalFactStep(op OperationalOperation, raw [32]byte, stage *OperationalStageProof) (operationalStepShape, error) {
	if raw == [32]byte{} {
		return operationalStepShape{}, errInvalidDurableRecord
	}
	ref, err := newDurableFactRef(raw[:])
	if err != nil {
		return operationalStepShape{}, err
	}
	return operationalStepShape{op: op, parts: []durableOperationInputPart{operationPartFactRef(ref)}, stage: stage,
		transition: func(r durableClaimRecord, at time.Time) (ClaimPhase, durableEffectFacts, optionalClaimTime, error) {
			if r.revision != claimRevision(op)-1 || r.phase.tag != durablePhaseEffectCapableAssigned {
				return nil, durableEffectFacts{}, noClaimTime(), errInvalidDurableRecord
			}
			phase, err := r.hydratePhase()
			facts := r.effects.clone()
			value := newDurableEffectRefTime(ref, at)
			switch op {
			case OperationalIntent:
				facts.intent = value
			case OperationalStamp:
				facts.staging = value
			case OperationalMark:
				facts.dispatch = value
			}
			return phase, facts, r.assignedAt, err
		}}, nil
}

const sqliteUpdateOperationalSQL = `
UPDATE reliable_submit_claims
SET phase_tag=?, run_ref=?, receipt_ref=?, revision=?, updated_at_unix_ns=?,
    assigned_at_unix_ns=?, effect_intent_ref=?, effect_intent_at_unix_ns=?,
    staging_ref=?, staging_at_unix_ns=?, dispatch_ref=?, dispatch_at_unix_ns=?,
    provider_observation_kind=?, provider_observation_ref=?, provider_observation_at_unix_ns=?,
    last_mutation_ref=?, latest_operation_kind=?, latest_operation_input_digest=?
WHERE claim_rowid=? AND codec_version=5 AND revision=? AND retention_state=1`

// operationalUpdateArgs binds one row update. It is separate from the
// statement's execution so a test can present the same row to the store
// triggers without the checks that precede it in a writer turn.
func operationalUpdateArgs(before, next durableClaimRecord) []any {
	f := next.effects
	return []any{int64(next.phase.tag), optionalOpaqueSQL(next.phase.run.ref),
		optionalOpaqueSQL(next.phase.receipt.ref), int64(next.revision), next.updatedAt.UnixNano(), optionalTimeSQL(next.assignedAt),
		optionalFactSQL(f.intent.ref), optionalTimeSQL(f.intent.at), optionalFactSQL(f.staging.ref), optionalTimeSQL(f.staging.at),
		optionalFactSQL(f.dispatch.ref), optionalTimeSQL(f.dispatch.at), int64(f.provider.kind), optionalFactSQL(f.provider.fact.ref),
		optionalTimeSQL(f.provider.fact.at), mutationRefBytes(next.lastMutation), operationKindSQL(next.latestOperation),
		operationInputBindingSQL(next.latestOperation), before.progressRowID, int64(before.revision)}
}

func (s *sqliteClaimStore) updateOperationalRow(ctx context.Context, conn *sql.Conn,
	before, next durableClaimRecord) (durableClaimRecord, error) {
	result, err := conn.ExecContext(ctx, sqliteUpdateOperationalSQL, operationalUpdateArgs(before, next)...)
	if err != nil {
		return durableClaimRecord{}, mapSQLiteError(err)
	}
	applied, err := result.RowsAffected()
	if err != nil || applied != 1 {
		return durableClaimRecord{}, errClaimStoreUnavailable
	}
	observed, err := s.selectSQLiteClaim(ctx, conn, next.claim)
	if err != nil || !observed.equal(next) {
		return durableClaimRecord{}, errClaimStoreUnavailable
	}
	return observed, nil
}
