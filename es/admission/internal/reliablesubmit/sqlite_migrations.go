package reliablesubmit

import "crypto/sha256"

const (
	sqliteClaimStoreApplicationID = 1163088467
	sqliteClaimStoreSchemaVersion = 2
	sqliteDefaultBusyTimeoutMS    = 5000
	sqliteDefaultMaxOpenConns     = 4
)

type sqliteMigration struct {
	version int
	name    string
	sql     string
}

var sqliteClaimStoreMigrations = []sqliteMigration{
	{
		version: 1,
		name:    "initial reliable submit claims",
		sql: `
CREATE TABLE reliable_submit_migrations (
  version INTEGER PRIMARY KEY CHECK (version > 0),
  name TEXT NOT NULL UNIQUE,
  applied_at_unix_ns INTEGER NOT NULL CHECK (applied_at_unix_ns > 0),
  source_sha256 TEXT NOT NULL CHECK (length(source_sha256) = 64)
) STRICT;

CREATE TABLE reliable_submit_claims (
  claim_rowid INTEGER PRIMARY KEY,
  caller_ref BLOB NOT NULL CHECK (length(caller_ref) > 0),
  submit_key_ref BLOB NOT NULL CHECK (length(submit_key_ref) > 0),
  plan_binding BLOB NOT NULL CHECK (length(plan_binding) > 0),
  witness_resolved_mask INTEGER NOT NULL CHECK (witness_resolved_mask BETWEEN 0 AND 16383),
  witness_inapplicable_mask INTEGER NOT NULL CHECK (witness_inapplicable_mask BETWEEN 0 AND 16383),
  phase_tag INTEGER NOT NULL CHECK (phase_tag BETWEEN 1 AND 7),
  run_ref BLOB CHECK (run_ref IS NULL OR length(run_ref) > 0),
  receipt_ref BLOB CHECK (receipt_ref IS NULL OR length(receipt_ref) > 0),
  revision INTEGER NOT NULL CHECK (revision > 0),
  created_at_unix_ns INTEGER NOT NULL CHECK (created_at_unix_ns > 0),
  updated_at_unix_ns INTEGER NOT NULL CHECK (updated_at_unix_ns >= created_at_unix_ns),
  assigned_at_unix_ns INTEGER CHECK (assigned_at_unix_ns IS NULL OR assigned_at_unix_ns >= created_at_unix_ns),
  effect_intent_ref BLOB CHECK (effect_intent_ref IS NULL OR length(effect_intent_ref) > 0),
  effect_intent_at_unix_ns INTEGER,
  staging_ref BLOB CHECK (staging_ref IS NULL OR length(staging_ref) > 0),
  staging_at_unix_ns INTEGER,
  dispatch_ref BLOB CHECK (dispatch_ref IS NULL OR length(dispatch_ref) > 0),
  dispatch_at_unix_ns INTEGER,
  provider_observation_kind INTEGER NOT NULL DEFAULT 0 CHECK (provider_observation_kind BETWEEN 0 AND 5),
  provider_observation_ref BLOB CHECK (provider_observation_ref IS NULL OR length(provider_observation_ref) > 0),
  provider_observation_at_unix_ns INTEGER,
  reconciliation_kind INTEGER NOT NULL DEFAULT 0 CHECK (reconciliation_kind BETWEEN 0 AND 6),
  reconciliation_ref BLOB CHECK (reconciliation_ref IS NULL OR length(reconciliation_ref) > 0),
  reconciliation_at_unix_ns INTEGER,
  expires_at_unix_ns INTEGER,
  retention_state INTEGER NOT NULL CHECK (retention_state BETWEEN 1 AND 3),
  unavailable_at_unix_ns INTEGER,
  unavailable_reason TEXT NOT NULL DEFAULT '',
  last_mutation_ref BLOB NOT NULL CHECK (length(last_mutation_ref) > 0),
  codec_version INTEGER NOT NULL CHECK (codec_version = 1),
  UNIQUE (caller_ref, submit_key_ref),
  CHECK ((witness_resolved_mask & witness_inapplicable_mask) = 0),
  CHECK ((witness_resolved_mask | witness_inapplicable_mask) = 16383),
  CHECK ((witness_inapplicable_mask & 7935) = 0),
  CHECK (
    (phase_tag IN (1, 2) AND run_ref IS NULL AND receipt_ref IS NULL AND assigned_at_unix_ns IS NULL) OR
    (phase_tag IN (3, 4, 5, 7) AND run_ref IS NOT NULL AND receipt_ref IS NULL AND assigned_at_unix_ns IS NOT NULL) OR
    (phase_tag = 6 AND run_ref IS NOT NULL AND receipt_ref IS NOT NULL AND assigned_at_unix_ns IS NOT NULL)
  ),
  CHECK ((effect_intent_ref IS NULL) = (effect_intent_at_unix_ns IS NULL)),
  CHECK ((staging_ref IS NULL) = (staging_at_unix_ns IS NULL)),
  CHECK ((dispatch_ref IS NULL) = (dispatch_at_unix_ns IS NULL)),
  CHECK ((provider_observation_ref IS NULL) = (provider_observation_at_unix_ns IS NULL)),
  CHECK ((provider_observation_kind = 0) = (provider_observation_ref IS NULL)),
  CHECK ((reconciliation_ref IS NULL) = (reconciliation_at_unix_ns IS NULL)),
  CHECK ((reconciliation_kind = 0) = (reconciliation_ref IS NULL)),
  CHECK (effect_intent_ref IS NULL OR run_ref IS NOT NULL),
  CHECK (staging_ref IS NULL OR effect_intent_ref IS NOT NULL),
  CHECK (dispatch_ref IS NULL OR effect_intent_ref IS NOT NULL),
  CHECK (provider_observation_ref IS NULL OR dispatch_ref IS NOT NULL),
  CHECK (
    provider_observation_kind = 0 OR
    (
      dispatch_ref IS NOT NULL AND run_ref IS NOT NULL AND
      (
        (provider_observation_kind = 1 AND phase_tag = 4) OR
        (provider_observation_kind IN (2, 5) AND phase_tag = 5) OR
        (provider_observation_kind = 3 AND phase_tag = 6) OR
        (provider_observation_kind = 4 AND phase_tag = 7)
      )
    )
  ),
  CHECK (
    reconciliation_kind = 0 OR
    (
      run_ref IS NOT NULL AND effect_intent_ref IS NOT NULL AND
      (
        (reconciliation_kind = 1 AND dispatch_ref IS NULL AND provider_observation_kind = 0 AND phase_tag = 3) OR
        (
          dispatch_ref IS NOT NULL AND
          (
            (reconciliation_kind = 2 AND phase_tag = 4) OR
            (reconciliation_kind IN (3, 6) AND phase_tag = 5) OR
            (reconciliation_kind = 4 AND phase_tag = 6) OR
            (reconciliation_kind = 5 AND phase_tag = 7)
          )
        )
      )
    )
  ),
  CHECK (phase_tag != 6 OR provider_observation_kind = 3),
  CHECK (phase_tag != 7 OR provider_observation_kind = 4 OR reconciliation_kind = 5),
  CHECK ((retention_state = 1 AND unavailable_at_unix_ns IS NULL AND unavailable_reason = '') OR
         (retention_state IN (2, 3) AND unavailable_at_unix_ns IS NOT NULL AND unavailable_reason != ''))
) STRICT;

CREATE TRIGGER reliable_submit_claims_no_delete
BEFORE DELETE ON reliable_submit_claims
BEGIN
  SELECT RAISE(ABORT, 'reliable submit claim deletion is forbidden');
END;

CREATE TRIGGER reliable_submit_claims_guard_update
BEFORE UPDATE ON reliable_submit_claims
BEGIN
  SELECT CASE WHEN NEW.caller_ref != OLD.caller_ref THEN RAISE(ABORT, 'immutable caller reference') END;
  SELECT CASE WHEN NEW.submit_key_ref != OLD.submit_key_ref THEN RAISE(ABORT, 'immutable submit key reference') END;
  SELECT CASE WHEN NEW.plan_binding != OLD.plan_binding THEN RAISE(ABORT, 'immutable plan binding') END;
  SELECT CASE WHEN NEW.witness_resolved_mask != OLD.witness_resolved_mask THEN RAISE(ABORT, 'immutable witness') END;
  SELECT CASE WHEN NEW.witness_inapplicable_mask != OLD.witness_inapplicable_mask THEN RAISE(ABORT, 'immutable witness') END;
  SELECT CASE WHEN NEW.created_at_unix_ns != OLD.created_at_unix_ns THEN RAISE(ABORT, 'immutable creation time') END;
  SELECT CASE WHEN NEW.codec_version != OLD.codec_version THEN RAISE(ABORT, 'immutable codec version') END;
  SELECT CASE WHEN NEW.revision != OLD.revision + 1 THEN RAISE(ABORT, 'revision must increment by one') END;
  SELECT CASE WHEN OLD.run_ref IS NOT NULL AND (NEW.run_ref IS NULL OR NEW.run_ref != OLD.run_ref) THEN RAISE(ABORT, 'immutable run reference') END;
  SELECT CASE WHEN OLD.receipt_ref IS NOT NULL AND (NEW.receipt_ref IS NULL OR NEW.receipt_ref != OLD.receipt_ref) THEN RAISE(ABORT, 'immutable receipt reference') END;
  SELECT CASE WHEN OLD.phase_tag IN (6, 7) AND NEW.phase_tag != OLD.phase_tag THEN RAISE(ABORT, 'terminal phase is immutable') END;
  SELECT CASE WHEN OLD.retention_state != 1 AND NEW.retention_state = 1 THEN RAISE(ABORT, 'inactive claim cannot become active') END;
END;
`,
	},
	{
		version: 2,
		name:    "latest operation descriptor",
		sql: `
ALTER TABLE reliable_submit_claims RENAME TO reliable_submit_claims_v1;

CREATE TABLE reliable_submit_claims (
  claim_rowid INTEGER PRIMARY KEY,
  caller_ref BLOB NOT NULL CHECK (length(caller_ref) > 0),
  submit_key_ref BLOB NOT NULL CHECK (length(submit_key_ref) > 0),
  plan_binding BLOB NOT NULL CHECK (length(plan_binding) > 0),
  witness_resolved_mask INTEGER NOT NULL CHECK (witness_resolved_mask BETWEEN 0 AND 16383),
  witness_inapplicable_mask INTEGER NOT NULL CHECK (witness_inapplicable_mask BETWEEN 0 AND 16383),
  phase_tag INTEGER NOT NULL CHECK (phase_tag BETWEEN 1 AND 7),
  run_ref BLOB CHECK (run_ref IS NULL OR length(run_ref) > 0),
  receipt_ref BLOB CHECK (receipt_ref IS NULL OR length(receipt_ref) > 0),
  revision INTEGER NOT NULL CHECK (revision > 0),
  created_at_unix_ns INTEGER NOT NULL CHECK (created_at_unix_ns > 0),
  updated_at_unix_ns INTEGER NOT NULL CHECK (updated_at_unix_ns >= created_at_unix_ns),
  assigned_at_unix_ns INTEGER CHECK (assigned_at_unix_ns IS NULL OR assigned_at_unix_ns >= created_at_unix_ns),
  effect_intent_ref BLOB CHECK (effect_intent_ref IS NULL OR length(effect_intent_ref) > 0),
  effect_intent_at_unix_ns INTEGER,
  staging_ref BLOB CHECK (staging_ref IS NULL OR length(staging_ref) > 0),
  staging_at_unix_ns INTEGER,
  dispatch_ref BLOB CHECK (dispatch_ref IS NULL OR length(dispatch_ref) > 0),
  dispatch_at_unix_ns INTEGER,
  provider_observation_kind INTEGER NOT NULL DEFAULT 0 CHECK (provider_observation_kind BETWEEN 0 AND 5),
  provider_observation_ref BLOB CHECK (provider_observation_ref IS NULL OR length(provider_observation_ref) > 0),
  provider_observation_at_unix_ns INTEGER,
  reconciliation_kind INTEGER NOT NULL DEFAULT 0 CHECK (reconciliation_kind BETWEEN 0 AND 6),
  reconciliation_ref BLOB CHECK (reconciliation_ref IS NULL OR length(reconciliation_ref) > 0),
  reconciliation_at_unix_ns INTEGER,
  expires_at_unix_ns INTEGER,
  retention_state INTEGER NOT NULL CHECK (retention_state BETWEEN 1 AND 3),
  unavailable_at_unix_ns INTEGER,
  unavailable_reason TEXT NOT NULL DEFAULT '',
  last_mutation_ref BLOB NOT NULL CHECK (length(last_mutation_ref) > 0),
  latest_operation_kind INTEGER CHECK (latest_operation_kind IS NULL OR latest_operation_kind BETWEEN 1 AND 10),
  latest_operation_input_digest BLOB CHECK (latest_operation_input_digest IS NULL OR length(latest_operation_input_digest) = 32),
  codec_version INTEGER NOT NULL CHECK (codec_version IN (1, 2)),
  UNIQUE (caller_ref, submit_key_ref),
  CHECK ((witness_resolved_mask & witness_inapplicable_mask) = 0),
  CHECK ((witness_resolved_mask | witness_inapplicable_mask) = 16383),
  CHECK ((witness_inapplicable_mask & 7935) = 0),
  CHECK (
    (phase_tag IN (1, 2) AND run_ref IS NULL AND receipt_ref IS NULL AND assigned_at_unix_ns IS NULL) OR
    (phase_tag IN (3, 4, 5, 7) AND run_ref IS NOT NULL AND receipt_ref IS NULL AND assigned_at_unix_ns IS NOT NULL) OR
    (phase_tag = 6 AND run_ref IS NOT NULL AND receipt_ref IS NOT NULL AND assigned_at_unix_ns IS NOT NULL)
  ),
  CHECK ((effect_intent_ref IS NULL) = (effect_intent_at_unix_ns IS NULL)),
  CHECK ((staging_ref IS NULL) = (staging_at_unix_ns IS NULL)),
  CHECK ((dispatch_ref IS NULL) = (dispatch_at_unix_ns IS NULL)),
  CHECK ((provider_observation_ref IS NULL) = (provider_observation_at_unix_ns IS NULL)),
  CHECK ((provider_observation_kind = 0) = (provider_observation_ref IS NULL)),
  CHECK ((reconciliation_ref IS NULL) = (reconciliation_at_unix_ns IS NULL)),
  CHECK ((reconciliation_kind = 0) = (reconciliation_ref IS NULL)),
  CHECK (effect_intent_ref IS NULL OR run_ref IS NOT NULL),
  CHECK (staging_ref IS NULL OR effect_intent_ref IS NOT NULL),
  CHECK (dispatch_ref IS NULL OR effect_intent_ref IS NOT NULL),
  CHECK (provider_observation_ref IS NULL OR dispatch_ref IS NOT NULL),
  CHECK (
    provider_observation_kind = 0 OR
    (
      dispatch_ref IS NOT NULL AND run_ref IS NOT NULL AND
      (
        (provider_observation_kind = 1 AND phase_tag = 4) OR
        (provider_observation_kind IN (2, 5) AND phase_tag = 5) OR
        (provider_observation_kind = 3 AND phase_tag = 6) OR
        (provider_observation_kind = 4 AND phase_tag = 7)
      )
    )
  ),
  CHECK (
    reconciliation_kind = 0 OR
    (
      run_ref IS NOT NULL AND effect_intent_ref IS NOT NULL AND
      (
        (reconciliation_kind = 1 AND dispatch_ref IS NULL AND provider_observation_kind = 0 AND phase_tag = 3) OR
        (
          dispatch_ref IS NOT NULL AND
          (
            (reconciliation_kind = 2 AND phase_tag = 4) OR
            (reconciliation_kind IN (3, 6) AND phase_tag = 5) OR
            (reconciliation_kind = 4 AND phase_tag = 6) OR
            (reconciliation_kind = 5 AND phase_tag = 7)
          )
        )
      )
    )
  ),
  CHECK (phase_tag != 6 OR provider_observation_kind = 3),
  CHECK (phase_tag != 7 OR provider_observation_kind = 4 OR reconciliation_kind = 5),
  CHECK ((retention_state = 1 AND unavailable_at_unix_ns IS NULL AND unavailable_reason = '') OR
         (retention_state IN (2, 3) AND unavailable_at_unix_ns IS NOT NULL AND unavailable_reason != '')),
  CHECK (
    (codec_version = 1 AND latest_operation_kind IS NULL AND latest_operation_input_digest IS NULL) OR
    (codec_version = 2 AND latest_operation_kind IS NOT NULL AND latest_operation_input_digest IS NOT NULL)
  )
) STRICT;

INSERT INTO reliable_submit_claims (
  claim_rowid,
  caller_ref,
  submit_key_ref,
  plan_binding,
  witness_resolved_mask,
  witness_inapplicable_mask,
  phase_tag,
  run_ref,
  receipt_ref,
  revision,
  created_at_unix_ns,
  updated_at_unix_ns,
  assigned_at_unix_ns,
  effect_intent_ref,
  effect_intent_at_unix_ns,
  staging_ref,
  staging_at_unix_ns,
  dispatch_ref,
  dispatch_at_unix_ns,
  provider_observation_kind,
  provider_observation_ref,
  provider_observation_at_unix_ns,
  reconciliation_kind,
  reconciliation_ref,
  reconciliation_at_unix_ns,
  expires_at_unix_ns,
  retention_state,
  unavailable_at_unix_ns,
  unavailable_reason,
  last_mutation_ref,
  latest_operation_kind,
  latest_operation_input_digest,
  codec_version
)
SELECT
  claim_rowid,
  caller_ref,
  submit_key_ref,
  plan_binding,
  witness_resolved_mask,
  witness_inapplicable_mask,
  phase_tag,
  run_ref,
  receipt_ref,
  revision,
  created_at_unix_ns,
  updated_at_unix_ns,
  assigned_at_unix_ns,
  effect_intent_ref,
  effect_intent_at_unix_ns,
  staging_ref,
  staging_at_unix_ns,
  dispatch_ref,
  dispatch_at_unix_ns,
  provider_observation_kind,
  provider_observation_ref,
  provider_observation_at_unix_ns,
  reconciliation_kind,
  reconciliation_ref,
  reconciliation_at_unix_ns,
  expires_at_unix_ns,
  retention_state,
  unavailable_at_unix_ns,
  unavailable_reason,
  last_mutation_ref,
  NULL,
  NULL,
  codec_version
FROM reliable_submit_claims_v1;

DROP TABLE reliable_submit_claims_v1;

CREATE TRIGGER reliable_submit_claims_no_delete
BEFORE DELETE ON reliable_submit_claims
BEGIN
  SELECT RAISE(ABORT, 'reliable submit claim deletion is forbidden');
END;

CREATE TRIGGER reliable_submit_claims_guard_insert_v2
BEFORE INSERT ON reliable_submit_claims
BEGIN
  SELECT CASE WHEN NEW.codec_version != 2 THEN RAISE(ABORT, 'new reliable submit rows require codec v2') END;
  SELECT CASE WHEN NEW.latest_operation_kind IS NULL THEN RAISE(ABORT, 'latest operation kind is required') END;
  SELECT CASE WHEN NEW.latest_operation_input_digest IS NULL THEN RAISE(ABORT, 'latest operation input digest is required') END;
END;

CREATE TRIGGER reliable_submit_claims_guard_update
BEFORE UPDATE ON reliable_submit_claims
BEGIN
  SELECT CASE WHEN NEW.caller_ref != OLD.caller_ref THEN RAISE(ABORT, 'immutable caller reference') END;
  SELECT CASE WHEN NEW.submit_key_ref != OLD.submit_key_ref THEN RAISE(ABORT, 'immutable submit key reference') END;
  SELECT CASE WHEN NEW.plan_binding != OLD.plan_binding THEN RAISE(ABORT, 'immutable plan binding') END;
  SELECT CASE WHEN NEW.witness_resolved_mask != OLD.witness_resolved_mask THEN RAISE(ABORT, 'immutable witness') END;
  SELECT CASE WHEN NEW.witness_inapplicable_mask != OLD.witness_inapplicable_mask THEN RAISE(ABORT, 'immutable witness') END;
  SELECT CASE WHEN NEW.created_at_unix_ns != OLD.created_at_unix_ns THEN RAISE(ABORT, 'immutable creation time') END;
  SELECT CASE WHEN NOT ((OLD.codec_version = 1 AND NEW.codec_version = 2) OR (OLD.codec_version = 2 AND NEW.codec_version = 2)) THEN RAISE(ABORT, 'codec version can only advance to v2') END;
  SELECT CASE WHEN NEW.revision != OLD.revision + 1 THEN RAISE(ABORT, 'revision must increment by one') END;
  SELECT CASE WHEN NEW.last_mutation_ref = OLD.last_mutation_ref THEN RAISE(ABORT, 'mutation reference must change with revision') END;
  SELECT CASE WHEN NEW.latest_operation_kind IS NULL THEN RAISE(ABORT, 'latest operation kind is required') END;
  SELECT CASE WHEN NEW.latest_operation_input_digest IS NULL THEN RAISE(ABORT, 'latest operation input digest is required') END;
  SELECT CASE WHEN OLD.run_ref IS NOT NULL AND (NEW.run_ref IS NULL OR NEW.run_ref != OLD.run_ref) THEN RAISE(ABORT, 'immutable run reference') END;
  SELECT CASE WHEN OLD.receipt_ref IS NOT NULL AND (NEW.receipt_ref IS NULL OR NEW.receipt_ref != OLD.receipt_ref) THEN RAISE(ABORT, 'immutable receipt reference') END;
  SELECT CASE WHEN OLD.phase_tag IN (6, 7) AND NEW.phase_tag != OLD.phase_tag THEN RAISE(ABORT, 'terminal phase is immutable') END;
  SELECT CASE WHEN OLD.retention_state != 1 AND NEW.retention_state = 1 THEN RAISE(ABORT, 'inactive claim cannot become active') END;
END;
`,
	},
}

func sqliteMigrationSHA256(sqlText string) string {
	sum := sha256.Sum256([]byte(sqlText))
	return fmtHex(sum[:])
}

func fmtHex(bytes []byte) string {
	const table = "0123456789abcdef"
	out := make([]byte, len(bytes)*2)
	for i, b := range bytes {
		out[i*2] = table[b>>4]
		out[i*2+1] = table[b&0x0f]
	}
	return string(out)
}
