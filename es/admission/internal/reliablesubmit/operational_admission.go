package reliablesubmit

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"time"
)

// OperationalAdmissionToken names the admission row a process presents at a
// first-effect cut: installation, epoch, admission generation and admission
// digest. The zero value means none. Only this package builds a nonzero
// token, and only from a row it has just read or written.
type OperationalAdmissionToken struct {
	privateReplayRedacted
	installation [32]byte
	epoch        uint64
	generation   uint64
	digest       [32]byte
}

// Valid reports whether the token names an admission row at all. It says
// nothing about whether that row is still the stored one.
func (t OperationalAdmissionToken) Valid() bool {
	return t.installation != [32]byte{} && t.epoch != 0 && t.generation != 0 && t.digest != [32]byte{}
}

// Names reports whether the token names exactly this installation, epoch and
// admission digest. The generation stays opaque to the caller.
func (t OperationalAdmissionToken) Names(installation [32]byte, epoch uint64, digest [32]byte) bool {
	return t.Valid() && t.installation == installation && t.epoch == epoch && t.digest == digest
}

func (t OperationalAdmissionToken) storable() bool {
	return t.Valid() && t.epoch <= math.MaxInt64 && t.generation <= math.MaxInt64
}

const (
	operationalAdmissionEnabled   int64 = 1
	operationalAdmissionWithdrawn int64 = 2
)

var errOperationalAdmissionRefused = errors.New("operational handoff: admission refused")

type operationalAdmissionRow struct {
	present   bool
	token     OperationalAdmissionToken
	state     int64
	updatedAt int64
}

// enabled is the token a first-effect cut must present. An uncommissioned or
// withdrawn domain has none.
func (r operationalAdmissionRow) enabled() OperationalAdmissionToken {
	if !r.present || r.state != operationalAdmissionEnabled {
		return OperationalAdmissionToken{}
	}
	return r.token
}

const sqliteSelectOperationalAdmissionSQL = `SELECT installation, epoch, generation, admission_digest, state, updated_at_unix_ns
FROM reliable_submit_operational_admission WHERE singleton=1`

func selectOperationalAdmission(ctx context.Context, conn *sql.Conn) (operationalAdmissionRow, error) {
	var installation, digest []byte
	var epoch, generation, state, updated int64
	err := conn.QueryRowContext(ctx, sqliteSelectOperationalAdmissionSQL).Scan(
		&installation, &epoch, &generation, &digest, &state, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return operationalAdmissionRow{}, nil
	}
	if err != nil {
		return operationalAdmissionRow{}, mapSQLiteError(err)
	}
	if len(installation) != 32 || len(digest) != 32 || epoch <= 0 || generation <= 0 || updated <= 0 ||
		(state != operationalAdmissionEnabled && state != operationalAdmissionWithdrawn) {
		return operationalAdmissionRow{}, errClaimStoreCorrupt
	}
	row := operationalAdmissionRow{present: true, state: state, updatedAt: updated}
	copy(row.token.installation[:], installation)
	copy(row.token.digest[:], digest)
	row.token.epoch, row.token.generation = uint64(epoch), uint64(generation)
	if !row.token.Valid() {
		return operationalAdmissionRow{}, errClaimStoreCorrupt
	}
	return row, nil
}

// operationalAdmissionForTurn reads the enabled token through a writer turn's
// own connection, so the comparison is serialized with the claim write.
func operationalAdmissionForTurn(ctx context.Context, conn *sql.Conn) (OperationalAdmissionToken, bool) {
	row, err := selectOperationalAdmission(ctx, conn)
	if err != nil {
		return OperationalAdmissionToken{}, false
	}
	return row.enabled(), true
}

// pooledOperationalAdmission reads the enabled token on a pooled connection.
// It is the hint before establishment and the release re-read after COMMIT;
// the writer turn's own read stays the authority.
func (s *sqliteClaimStore) pooledOperationalAdmission(ctx context.Context) (OperationalAdmissionToken, bool) {
	if ctx.Err() != nil {
		return OperationalAdmissionToken{}, false
	}
	conn, err := s.checkedConn(ctx)
	if err != nil {
		return OperationalAdmissionToken{}, false
	}
	row, err := selectOperationalAdmission(ctx, conn)
	if err != nil || ctx.Err() != nil {
		_ = discardUncertainSQLiteConn(conn)
		_ = conn.Close()
		return OperationalAdmissionToken{}, false
	}
	if conn.Close() != nil {
		return OperationalAdmissionToken{}, false
	}
	return row.enabled(), true
}

// AdmissionHint reads the enabled admission token outside a writer turn, so a
// caller that has been fenced can refuse before it asks for one. It decides
// nothing: only the comparison inside a writer turn does.
func (a *OperationalAccess) AdmissionHint(ctx context.Context) (OperationalAdmissionToken, bool) {
	if a == nil || a.self != a || !a.life.live() || ctx.Err() != nil || a.issuer.qualify() != nil {
		return OperationalAdmissionToken{}, false
	}
	return a.issuer.base.store.pooledOperationalAdmission(ctx)
}

// operationalAdmissionWrite owns the one writer transaction of commission,
// advance and withdrawal. The step decides from the row read under the writer
// lock and either writes once or reports that the wanted row already exists.
// An unknown COMMIT outcome is an error: the caller stays closed and calls
// again, which is safe because each operation is idempotent by content.
// It holds the custody lock in read mode, which is not reentrant: it must not
// be reached from a callback of a borrow on the same handle.
func (c *OperationalCustody) operationalAdmissionWrite(ctx context.Context,
	step func(conn *sql.Conn, row operationalAdmissionRow, now int64) (operationalAdmissionRow, bool, error)) (out operationalAdmissionRow, outErr error) {
	if c == nil || c.self != c {
		return operationalAdmissionRow{}, errClaimStoreUnavailable
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.base == nil || ctx.Err() != nil || c.qualify() != nil {
		return operationalAdmissionRow{}, errClaimStoreUnavailable
	}
	conn, err := c.base.store.checkedConn(ctx)
	if err != nil {
		return operationalAdmissionRow{}, errClaimStoreUnavailable
	}
	defer conn.Close()
	if err := beginImmediate(ctx, conn); err != nil {
		return operationalAdmissionRow{}, errClaimStoreUnavailable
	}
	commitAttempted := false
	defer func() {
		if commitAttempted {
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := conn.ExecContext(cleanup, "ROLLBACK")
		timely := cleanup.Err() == nil
		cancel()
		if err != nil || !timely {
			_ = discardUncertainSQLiteConn(conn)
			out, outErr = operationalAdmissionRow{}, errClaimStoreUnavailable
		}
	}()
	if c.qualify() != nil || verifySQLiteStoreCurrent(ctx, conn) != nil {
		return operationalAdmissionRow{}, errClaimStoreUnavailable
	}
	row, err := selectOperationalAdmission(ctx, conn)
	if err != nil {
		return operationalAdmissionRow{}, err
	}
	now := time.Now().UnixNano()
	if row.present && now < row.updatedAt {
		now = row.updatedAt
	}
	want, wrote, err := step(conn, row, now)
	if err != nil {
		return operationalAdmissionRow{}, err
	}
	if !wrote {
		return want, nil
	}
	written, err := selectOperationalAdmission(ctx, conn)
	if err != nil || written != want || ctx.Err() != nil {
		return operationalAdmissionRow{}, errClaimStoreUnavailable
	}
	commitAttempted = true
	attempt := commit
	if c.admissionCommit != nil {
		attempt = c.admissionCommit
	}
	if err := attempt(ctx, conn); err != nil {
		_ = discardUncertainSQLiteConn(conn)
		return operationalAdmissionRow{}, errClaimStoreCommitUnknown
	}
	return want, nil
}

// CommissionOperationalAdmission creates generation 1 on an empty domain, or
// adopts the stored generation when the enabled row already carries the same
// installation, epoch and digest. Anything else is refused. It has no
// production caller.
func (c *OperationalCustody) CommissionOperationalAdmission(ctx context.Context, installation [32]byte, epoch uint64,
	digest [32]byte) (OperationalAdmissionToken, error) {
	first := OperationalAdmissionToken{installation: installation, epoch: epoch, generation: 1, digest: digest}
	if !first.storable() {
		return OperationalAdmissionToken{}, errOperationalAdmissionRefused
	}
	row, err := c.operationalAdmissionWrite(ctx, func(conn *sql.Conn, row operationalAdmissionRow, now int64) (operationalAdmissionRow, bool, error) {
		if row.present {
			if row.state != operationalAdmissionEnabled || row.token.installation != installation ||
				row.token.epoch != epoch || row.token.digest != digest {
				return operationalAdmissionRow{}, false, errOperationalAdmissionRefused
			}
			return row, false, nil
		}
		if _, err := conn.ExecContext(ctx, `INSERT INTO reliable_submit_operational_admission
(singleton, installation, epoch, generation, admission_digest, state, updated_at_unix_ns)
VALUES (1, ?, ?, 1, ?, 1, ?)`, installation[:], int64(epoch), digest[:], now); err != nil {
			return operationalAdmissionRow{}, false, mapSQLiteError(err)
		}
		return operationalAdmissionRow{present: true, token: first, state: operationalAdmissionEnabled, updatedAt: now}, true, nil
	})
	if err != nil {
		return OperationalAdmissionToken{}, err
	}
	return row.enabled(), nil
}

// AdvanceOperationalAdmission replaces the domain's admission content. The
// row must be at the expected generation with a different digest, enabled or
// withdrawn; it becomes the next generation, enabled. A row already at the
// next generation with this digest and enabled is success. Anything else is
// refused. It has no production caller.
func (c *OperationalCustody) AdvanceOperationalAdmission(ctx context.Context, installation [32]byte, epoch uint64,
	digest [32]byte, expectedGeneration uint64) (OperationalAdmissionToken, error) {
	if expectedGeneration == 0 || expectedGeneration >= math.MaxInt64 {
		return OperationalAdmissionToken{}, errOperationalAdmissionRefused
	}
	next := OperationalAdmissionToken{installation: installation, epoch: epoch, generation: expectedGeneration + 1, digest: digest}
	if !next.storable() {
		return OperationalAdmissionToken{}, errOperationalAdmissionRefused
	}
	row, err := c.operationalAdmissionWrite(ctx, func(conn *sql.Conn, row operationalAdmissionRow, now int64) (operationalAdmissionRow, bool, error) {
		if !row.present || row.token.installation != installation || row.token.epoch != epoch {
			return operationalAdmissionRow{}, false, errOperationalAdmissionRefused
		}
		if row.token == next && row.state == operationalAdmissionEnabled {
			return row, false, nil
		}
		if row.token.generation != expectedGeneration || row.token.digest == digest {
			return operationalAdmissionRow{}, false, errOperationalAdmissionRefused
		}
		result, err := conn.ExecContext(ctx, `UPDATE reliable_submit_operational_admission
SET generation=?, admission_digest=?, state=1, updated_at_unix_ns=?
WHERE singleton=1 AND generation=?`, int64(next.generation), digest[:], now, int64(expectedGeneration))
		if err != nil {
			return operationalAdmissionRow{}, false, mapSQLiteError(err)
		}
		if affected, err := result.RowsAffected(); err != nil || affected != 1 {
			return operationalAdmissionRow{}, false, errClaimStoreUnavailable
		}
		return operationalAdmissionRow{present: true, token: next, state: operationalAdmissionEnabled, updatedAt: now}, true, nil
	})
	if err != nil {
		return OperationalAdmissionToken{}, err
	}
	return row.enabled(), nil
}

// WithdrawOperationalAdmission disables first effects for the whole domain.
// The presented token must name the stored installation and epoch; its
// generation need not match, so a process that has been fenced can still stop
// the domain. An already withdrawn row is success. It has no production
// caller.
func (c *OperationalCustody) WithdrawOperationalAdmission(ctx context.Context, token OperationalAdmissionToken) error {
	if !token.Valid() {
		return errOperationalAdmissionRefused
	}
	_, err := c.operationalAdmissionWrite(ctx, func(conn *sql.Conn, row operationalAdmissionRow, now int64) (operationalAdmissionRow, bool, error) {
		if !row.present || row.token.installation != token.installation || row.token.epoch != token.epoch {
			return operationalAdmissionRow{}, false, errOperationalAdmissionRefused
		}
		if row.state == operationalAdmissionWithdrawn {
			return row, false, nil
		}
		result, err := conn.ExecContext(ctx, `UPDATE reliable_submit_operational_admission
SET state=2, updated_at_unix_ns=?
WHERE singleton=1 AND state=1`, now)
		if err != nil {
			return operationalAdmissionRow{}, false, mapSQLiteError(err)
		}
		if affected, err := result.RowsAffected(); err != nil || affected != 1 {
			return operationalAdmissionRow{}, false, errClaimStoreUnavailable
		}
		row.state, row.updatedAt = operationalAdmissionWithdrawn, now
		return row, true, nil
	})
	return err
}

// ConfigureOperationalReleaseProofForProof installs a nil-default observer
// that runs after a directly acknowledged COMMIT and before the release
// re-read. It receives only the operation and returns nothing, so it can order
// a test's collaborators but cannot grant, refuse or change anything.
func (c *OperationalCustody) ConfigureOperationalReleaseProofForProof(observe func(OperationalOperation)) error {
	if c == nil || c.self != c {
		return errClaimStoreUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.base == nil {
		return errClaimStoreUnavailable
	}
	c.releaseProof = observe
	return nil
}
