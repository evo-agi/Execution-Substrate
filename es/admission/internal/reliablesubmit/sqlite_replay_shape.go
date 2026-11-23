package reliablesubmit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
)

// These hashes bind the complete non-internal sqlite_schema rows created by
// the literal migrations under the pinned SQLite driver. A schema row
// includes the table definition (including STRICT, CHECK, and FK clauses),
// named indexes, and the complete trigger body. They are deliberately not
// learned from an existing database during open.
const (
	sqliteSchema1SHA256 = "031abaada34a63834d3466081ed04afef6b7c9f55103cd2b57fe3033b8c45ef0"
	sqliteSchema2SHA256 = "944094f4e5fae102ea2882a076f580c69494678f41acedf9eaa971fe836eb280"
	sqliteSchema3SHA256 = "15ab48bde4d53bb252dc954a2aa3b1db12de7295111f23bb0264f74f153dba92"
	sqliteSchema4SHA256 = "2ae4721c8526ed9b8de35fd3acdfa31448eae9b547ba8662a22ed130035f7c15"
	sqliteSchema5SHA256 = "7d545c736a508293321e1f757c402144b05a7b194153226053717768960eae27"
)

// SQLite reserves the literal ASCII prefix sqlite_ for internal objects.
const sqliteUserSchemaPredicate = `substr(name, 1, 7) COLLATE NOCASE <> 'sqlite_'`

func sqliteSchemaDigest(ctx context.Context, conn *sql.Conn) (string, error) {
	rows, err := conn.QueryContext(ctx, `SELECT type, name, tbl_name, sql
FROM sqlite_schema WHERE `+sqliteUserSchemaPredicate+` ORDER BY name COLLATE BINARY`)
	if err != nil {
		return "", mapSQLiteError(err)
	}
	defer rows.Close()
	h := sha256.New()
	var width [8]byte
	count := 0
	for rows.Next() {
		var kind, name, table string
		var statement sql.NullString
		if err := rows.Scan(&kind, &name, &table, &statement); err != nil {
			return "", mapSQLiteError(err)
		}
		if !statement.Valid || count >= 64 {
			return "", errClaimStoreUnsupported
		}
		for _, part := range []string{kind, name, table, statement.String} {
			binary.BigEndian.PutUint64(width[:], uint64(len(part)))
			_, _ = h.Write(width[:])
			_, _ = h.Write([]byte(part))
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return "", mapSQLiteError(err)
	}
	if count == 0 {
		return "", errClaimStoreUnsupported
	}
	return fmtHex(h.Sum(nil)), nil
}

func verifySQLiteSchemaShape(ctx context.Context, conn *sql.Conn, version int) error {
	var expected string
	switch version {
	case 1:
		expected = sqliteSchema1SHA256
	case 2:
		expected = sqliteSchema2SHA256
	case 3:
		expected = sqliteSchema3SHA256
	case 4:
		expected = sqliteSchema4SHA256
	case 5:
		expected = sqliteSchema5SHA256
	default:
		return errClaimStoreUnsupported
	}
	actual, err := sqliteSchemaDigest(ctx, conn)
	if err != nil {
		return err
	}
	if expected == "" || actual != expected {
		return errClaimStoreUnsupported
	}
	rows, err := conn.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return mapSQLiteError(err)
	}
	defer rows.Close()
	if rows.Next() {
		return errClaimStoreCorrupt
	}
	if err := rows.Err(); err != nil {
		return mapSQLiteError(err)
	}
	return nil
}
