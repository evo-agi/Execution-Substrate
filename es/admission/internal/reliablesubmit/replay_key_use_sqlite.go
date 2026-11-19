package reliablesubmit

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"math"
	"sync"
	"time"
)

const (
	replayKeyPurposeBinding         = 1
	replayKeyPurposeEnvelope        = 2
	replayKeyStateActive            = 1
	replayKeyStateRetired           = 2
	replayKeyStateRevoked           = 3
	replayMaxKeyGrants       uint64 = 1 << 32
	replayFixtureGrantLimit  uint64 = 32
)

// PrivateReplayKeys is one injected synthetic pair. It has no public config,
// production loader, formatter of bytes, or JSON/text serialization contract.
type PrivateReplayKeys struct {
	privateReplayRedacted
	bindingID  string
	envelopeID string
	binding    [32]byte
	envelope   [32]byte
	bindingFP  [32]byte
	envelopeFP [32]byte
	valid      bool
}

func NewPrivateReplayKeys(bindingID string, bindingBytes []byte, envelopeID string, envelopeBytes []byte) (PrivateReplayKeys, error) {
	if !replayKeyIDValid(bindingID) || !replayKeyIDValid(envelopeID) ||
		bindingID == envelopeID || len(bindingBytes) != 32 || len(envelopeBytes) != 32 ||
		subtle.ConstantTimeCompare(bindingBytes, envelopeBytes) == 1 {
		return PrivateReplayKeys{}, errClaimStoreUnsupported
	}
	keys := PrivateReplayKeys{bindingID: bindingID, envelopeID: envelopeID, valid: true}
	copy(keys.binding[:], bindingBytes)
	copy(keys.envelope[:], envelopeBytes)
	keys.bindingFP = replayKeyFingerprint(keys.binding)
	keys.envelopeFP = replayKeyFingerprint(keys.envelope)
	return keys, nil
}

func replayKeyFingerprint(key [32]byte) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("ESRSKEY1"))
	_, _ = h.Write(key[:])
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

type privateSealPermit struct {
	privateReplayRedacted
	mu           sync.Mutex
	used         bool
	issuer       *sqliteClaimStore
	keyID        string
	fingerprint  [32]byte
	frozenDigest [32]byte
	sequence     uint64
}

func (p *privateSealPermit) consume(issuer *sqliteClaimStore, keyID string, fingerprint [32]byte, frozenDigest [32]byte) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.used {
		return false
	}
	p.used = true // even a mismatch burns this process-local permit
	return issuer != nil && p.issuer == issuer && p.keyID == keyID && p.sequence > 0 &&
		subtle.ConstantTimeCompare(p.fingerprint[:], fingerprint[:]) == 1 &&
		subtle.ConstantTimeCompare(p.frozenDigest[:], frozenDigest[:]) == 1
}

func (p *privateSealPermit) burn() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.used = true
	p.mu.Unlock()
}

func (s *sqliteClaimStore) registerOrCompareReplayKey(ctx context.Context, conn *sql.Conn, id string, purpose int, fingerprint [32]byte, activeOnly bool) error {
	if !replayKeyIDValid(id) || (purpose != 1 && purpose != 2) {
		return errClaimStoreUnsupported
	}
	var recordedPurpose, state int
	var recordedFP []byte
	err := conn.QueryRowContext(ctx, `SELECT purpose,material_fingerprint,state
FROM reliable_submit_key_registry WHERE key_id=? COLLATE BINARY`, id).Scan(&recordedPurpose, &recordedFP, &state)
	if errors.Is(err, sql.ErrNoRows) {
		if !activeOnly {
			return errClaimStoreUnavailable
		}
		if _, err := conn.ExecContext(ctx, `INSERT INTO reliable_submit_key_registry
(key_id,purpose,material_fingerprint,state) VALUES (?,?,?,1)`, id, purpose, fingerprint[:]); err != nil {
			return mapSQLiteError(err)
		}
		return nil
	}
	if err != nil {
		return mapSQLiteError(err)
	}
	if recordedPurpose != purpose || len(recordedFP) != 32 ||
		subtle.ConstantTimeCompare(recordedFP, fingerprint[:]) != 1 ||
		state == replayKeyStateRevoked || (activeOnly && state != replayKeyStateActive) ||
		state < replayKeyStateActive || state > replayKeyStateRevoked {
		return errClaimStoreUnavailable
	}
	return nil
}

const a1ReadRollbackBudget = 5 * time.Second

type a1ReadTransactionState uint8

const (
	a1ReadNotDispatched a1ReadTransactionState = iota
	a1ReadBeginDispatched
	a1ReadKnownBegun
	a1ReadCommitAttempted
	a1ReadKnownEnded
)

// A nonnil first response may itself be uncertain. The second attempt is
// always the unchanged real exact-connection primitive, never a semantic retry.
func (s *sqliteClaimStore) discardA1ReadConnection(conn *sql.Conn) bool {
	first := discardUncertainSQLiteConn
	if s.a1ReadDiscardAttempt != nil {
		first = s.a1ReadDiscardAttempt
	}
	if first(conn) == nil {
		return true
	}
	return discardUncertainSQLiteConn(conn) == nil
}

func (s *sqliteClaimStore) checkOriginalReplayKeys(ctx context.Context, keys PrivateReplayKeys, activeOnly bool) (out error) {
	if !keys.valid {
		return errClaimStoreUnsupported
	}
	if ctx.Err() != nil {
		return errClaimStoreUnavailable
	}
	conn, err := s.checkedConn(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return errClaimStoreUnavailable
		}
		return err
	}
	state := a1ReadNotDispatched
	safeRelease := true
	defer func() {
		switch state {
		case a1ReadBeginDispatched, a1ReadCommitAttempted:
			// Decide against ordinary pool return before disposal. No
			// ROLLBACK follows an attempted read COMMIT.
			safeRelease = false
			safeRelease = s.discardA1ReadConnection(conn)
			out = errClaimStoreUnavailable
		case a1ReadKnownBegun:
			cleanupCtx, cancel := context.WithTimeout(context.Background(), a1ReadRollbackBudget)
			rollback := func(ctx context.Context, conn *sql.Conn) error {
				_, err := conn.ExecContext(ctx, "ROLLBACK")
				return err
			}
			if s.a1ReadRollbackAttempt != nil {
				rollback = s.a1ReadRollbackAttempt
			}
			rollbackErr := rollback(cleanupCtx, conn)
			cleanupErr := cleanupCtx.Err() // observe before our own cancel changes the context
			cancel()
			if rollbackErr != nil || cleanupErr != nil {
				safeRelease = false
				safeRelease = s.discardA1ReadConnection(conn)
				out = errClaimStoreUnavailable
			} else if ctx.Err() != nil {
				// Confirmed cleanup cannot convert a canceled request to success.
				out = errClaimStoreUnavailable
			}
		}
		if safeRelease {
			_ = conn.Close()
		}
	}()
	if ctx.Err() != nil {
		return errClaimStoreUnavailable
	}
	begin := beginRead
	if s.a1ReadBeginAttempt != nil {
		begin = s.a1ReadBeginAttempt
	}
	state = a1ReadBeginDispatched
	if err := begin(ctx, conn); err != nil {
		return errClaimStoreUnavailable
	}
	state = a1ReadKnownBegun
	if s.a1ReadAfterBegin != nil {
		if err := s.a1ReadAfterBegin(conn); err != nil {
			return err
		}
	}
	if err := s.registerOrCompareReplayKey(ctx, conn, keys.bindingID, 1, keys.bindingFP, false); err != nil {
		return err
	}
	if s.a1ReadAfterFirstKey != nil {
		if err := s.a1ReadAfterFirstKey(conn); err != nil {
			return err
		}
	}
	if err := s.registerOrCompareReplayKey(ctx, conn, keys.envelopeID, 2, keys.envelopeFP, false); err != nil {
		return err
	}
	if activeOnly {
		// The read path never registers a missing key, and a retired original
		// remains usable only when this flag is false.
		for _, id := range []string{keys.bindingID, keys.envelopeID} {
			var state int
			if err := conn.QueryRowContext(ctx, `SELECT state FROM reliable_submit_key_registry WHERE key_id=? COLLATE BINARY`, id).Scan(&state); err != nil || state != replayKeyStateActive {
				return errClaimStoreUnavailable
			}
		}
	}
	if ctx.Err() != nil {
		return errClaimStoreUnavailable
	}
	commitRead := commit
	if s.a1ReadCommitAttempt != nil {
		commitRead = s.a1ReadCommitAttempt
	}
	state = a1ReadCommitAttempted
	if err := commitRead(ctx, conn); err != nil {
		return errClaimStoreUnavailable
	}
	state = a1ReadKnownEnded
	if ctx.Err() != nil {
		return errClaimStoreUnavailable
	}
	return nil
}

func (s *sqliteClaimStore) consumeReplaySealPermit(ctx context.Context, keys PrivateReplayKeys, frozenDigest [32]byte, permit *privateSealPermit) error {
	accepted := permit.consume(s, keys.envelopeID, keys.envelopeFP, frozenDigest)
	if !keys.valid || !accepted {
		return errClaimStoreUnavailable
	}
	if err := s.checkOriginalReplayKeys(ctx, keys, true); err != nil {
		return errClaimStoreUnavailable
	}
	return nil
}

func (s *sqliteClaimStore) reserveReplaySealUse(ctx context.Context, keys PrivateReplayKeys, frozenDigest [32]byte, isolatedLifetimeProfile bool) (permit *privateSealPermit, out error) {
	if !keys.valid {
		return nil, errClaimStoreUnsupported
	}
	conn, err := s.checkedConn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := s.beginImmediate(ctx, conn); err != nil {
		return nil, err
	}
	commitAttempted := false
	defer func() {
		if !commitAttempted {
			if _, err := conn.ExecContext(context.Background(), "ROLLBACK"); err != nil {
				permit = nil
				if discardUncertainSQLiteConn(conn) != nil {
					out = errClaimStoreUnavailable
				} else {
					out = errClaimStoreCommitUnknown
				}
			}
		}
	}()
	if err := s.registerOrCompareReplayKey(ctx, conn, keys.bindingID, 1, keys.bindingFP, true); err != nil {
		return nil, err
	}
	if err := s.registerOrCompareReplayKey(ctx, conn, keys.envelopeID, 2, keys.envelopeFP, true); err != nil {
		return nil, err
	}
	var count int64
	err = conn.QueryRowContext(ctx, `SELECT granted_count FROM reliable_submit_seal_use WHERE envelope_key_id=? COLLATE BINARY`, keys.envelopeID).Scan(&count)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err := conn.ExecContext(ctx, `INSERT INTO reliable_submit_seal_use(envelope_key_id,granted_count) VALUES (?,0)`, keys.envelopeID); err != nil {
			return nil, mapSQLiteError(err)
		}
		count = 0
	} else if err != nil {
		return nil, mapSQLiteError(err)
	}
	if count < 0 || uint64(count) >= replayMaxKeyGrants {
		return nil, errClaimStoreUnsupported
	}
	rows, err := conn.QueryContext(ctx, `SELECT granted_count FROM reliable_submit_seal_use`)
	if err != nil {
		return nil, mapSQLiteError(err)
	}
	var aggregate uint64
	for rows.Next() {
		var n int64
		if err := rows.Scan(&n); err != nil {
			_ = rows.Close()
			return nil, mapSQLiteError(err)
		}
		if n < 0 || uint64(n) > replayMaxKeyGrants || aggregate > math.MaxUint64-uint64(n) {
			_ = rows.Close()
			return nil, errClaimStoreCorrupt
		}
		aggregate += uint64(n)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, mapSQLiteError(err)
	}
	if err := rows.Close(); err != nil {
		return nil, mapSQLiteError(err)
	}
	if !isolatedLifetimeProfile && aggregate >= replayFixtureGrantLimit {
		return nil, errClaimStoreUnsupported
	}
	result, err := conn.ExecContext(ctx, `UPDATE reliable_submit_seal_use
SET granted_count=granted_count+1 WHERE envelope_key_id=? COLLATE BINARY AND granted_count=?`, keys.envelopeID, count)
	if err != nil {
		return nil, mapSQLiteError(err)
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		return nil, errClaimStoreUnavailable
	}
	commitAttempted = true
	commitGrantAttempt := commit
	if s.sealGrantCommit != nil {
		commitGrantAttempt = s.sealGrantCommit
	}
	commitGrant := func(ctx context.Context, conn *sql.Conn) error {
		if err := commitGrantAttempt(ctx, conn); err != nil {
			if discardUncertainSQLiteConn(conn) != nil {
				return errClaimStoreUnavailable
			}
			return err
		}
		return nil
	}
	if err := commitGrant(ctx, conn); err != nil {
		return nil, err
	}
	return &privateSealPermit{issuer: s, keyID: keys.envelopeID, fingerprint: keys.envelopeFP,
		frozenDigest: frozenDigest, sequence: uint64(count) + 1}, nil
}

func (s *sqliteClaimStore) transitionReplayKeyState(ctx context.Context, id string, target int) (out error) {
	if !replayKeyIDValid(id) || (target != replayKeyStateRetired && target != replayKeyStateRevoked) {
		return errClaimStoreUnsupported
	}
	conn, err := s.checkedConn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := s.beginImmediate(ctx, conn); err != nil {
		return err
	}
	commitAttempted := false
	defer func() {
		if !commitAttempted {
			if _, err := conn.ExecContext(context.Background(), "ROLLBACK"); err != nil {
				if discardUncertainSQLiteConn(conn) != nil {
					out = errClaimStoreUnavailable
				} else {
					out = errClaimStoreCommitUnknown
				}
			}
		}
	}()
	result, err := conn.ExecContext(ctx, `UPDATE reliable_submit_key_registry SET state=?
WHERE key_id=? COLLATE BINARY`, target, id)
	if err != nil {
		return mapSQLiteError(err)
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		return errClaimStoreUnavailable
	}
	commitAttempted = true
	if err := commit(ctx, conn); err != nil {
		if discardUncertainSQLiteConn(conn) != nil {
			return errClaimStoreUnavailable
		}
		return err
	}
	return nil
}
