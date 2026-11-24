package reliablesubmit

// Migration 5 carries every existing row forward and admits only the
// selected operational phases and irreversible progress transitions. It also
// creates the one-row operational admission table. The claim rows are copied
// before any trigger exists, and both admission clauses apply to codec 5 only.
const sqliteMigration5SQL = `
CREATE TEMP TABLE replay_m5_key_before AS SELECT rowid, key_id, purpose, material_fingerprint, state FROM reliable_submit_key_registry;
CREATE TEMP TABLE replay_m5_grant_before AS SELECT rowid, envelope_key_id, granted_count FROM reliable_submit_seal_use;
CREATE TEMP TABLE replay_m5_ledger_before AS SELECT version, name, applied_at_unix_ns, source_sha256 FROM reliable_submit_migrations;
DROP TRIGGER reliable_submit_claims_no_delete;
DROP TRIGGER reliable_submit_claims_guard_insert_v4;
DROP TRIGGER reliable_submit_claims_guard_update;
ALTER TABLE reliable_submit_claims RENAME TO reliable_submit_claims_v4;
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
  codec_version INTEGER NOT NULL CHECK (codec_version IN (1, 2, 3, 4, 5)),

  replay_scope INTEGER,
  intent_format INTEGER,
  intent_commitment BLOB,
  context_commitment BLOB,
  envelope_wrapper_format INTEGER,
  envelope_payload_format INTEGER,
  envelope_algorithm INTEGER,
  envelope_ref TEXT,
  envelope_size INTEGER,
  envelope_sha256 BLOB,
  binding_key_id TEXT REFERENCES reliable_submit_key_registry(key_id),
  binding_key_fingerprint BLOB,
  envelope_key_id TEXT REFERENCES reliable_submit_key_registry(key_id),
  envelope_key_fingerprint BLOB,
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
    codec_version = 4 OR reconciliation_kind = 0 OR
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
  CHECK (codec_version != 4 OR reconciliation_kind = 0 OR (
    run_ref IS NOT NULL AND effect_intent_ref IS NOT NULL
    AND reconciliation_at_unix_ns >= effect_intent_at_unix_ns
    AND (
      (reconciliation_kind = 1 AND (
        (dispatch_ref IS NULL AND provider_observation_kind = 0 AND phase_tag = 3)
        OR (dispatch_ref IS NOT NULL AND phase_tag BETWEEN 3 AND 7
          AND reconciliation_at_unix_ns <= dispatch_at_unix_ns)
      ))
      OR (dispatch_ref IS NOT NULL AND reconciliation_at_unix_ns >= dispatch_at_unix_ns
        AND ((reconciliation_kind IN (2,3,6) AND phase_tag BETWEEN 4 AND 7)
          OR (reconciliation_kind = 4 AND phase_tag = 6)
          OR (reconciliation_kind = 5 AND phase_tag = 7)))
    )
  )),
  CHECK (phase_tag != 6 OR provider_observation_kind = 3),
  CHECK (phase_tag != 7 OR provider_observation_kind = 4 OR reconciliation_kind = 5),
  CHECK ((retention_state = 1 AND unavailable_at_unix_ns IS NULL AND unavailable_reason = '') OR
         (retention_state IN (2, 3) AND unavailable_at_unix_ns IS NOT NULL AND unavailable_reason != '')),
  CHECK (
    (codec_version = 1 AND latest_operation_kind IS NULL AND latest_operation_input_digest IS NULL) OR
    (codec_version IN (2, 3, 4, 5) AND latest_operation_kind IS NOT NULL AND latest_operation_input_digest IS NOT NULL)
  ),
  CHECK (
    (codec_version IN (1, 2) AND replay_scope IS NULL AND intent_format IS NULL AND intent_commitment IS NULL AND context_commitment IS NULL AND envelope_wrapper_format IS NULL AND envelope_payload_format IS NULL AND envelope_algorithm IS NULL AND envelope_ref IS NULL AND envelope_size IS NULL AND envelope_sha256 IS NULL AND binding_key_id IS NULL AND binding_key_fingerprint IS NULL AND envelope_key_id IS NULL AND envelope_key_fingerprint IS NULL)
    OR (codec_version IN (3,4,5)
      AND length(caller_ref) = 32
      AND length(submit_key_ref) = 32
      AND length(plan_binding) BETWEEN 1 AND 256
      AND replay_scope IS CASE codec_version WHEN 3 THEN 1 WHEN 4 THEN 2 ELSE 3 END
      AND intent_format IS 1
      AND typeof(intent_commitment)='blob' AND length(intent_commitment)=32
      AND typeof(context_commitment)='blob' AND length(context_commitment)=32
      AND envelope_wrapper_format IS CASE codec_version WHEN 3 THEN 1 WHEN 4 THEN 2 ELSE 3 END
      AND envelope_payload_format IS CASE codec_version WHEN 3 THEN 1 WHEN 4 THEN 2 ELSE 3 END
      AND envelope_algorithm IS 1
      AND CASE WHEN typeof(envelope_ref)='text'
      AND instr(envelope_ref,char(0)) IS 0
      AND length(CAST(envelope_ref AS BLOB))=75
      AND substr(envelope_ref,1,11)='objects/v1/' COLLATE BINARY
      AND length(CAST(substr(envelope_ref,12) AS BLOB))=64
      AND substr(envelope_ref,12) NOT GLOB '*[^0-9a-f]*'
    THEN 1 ELSE 0 END = 1
      AND envelope_size IS NOT NULL AND envelope_size BETWEEN 29 AND 2097152
      AND typeof(envelope_sha256)='blob' AND length(envelope_sha256)=32
      AND CASE WHEN typeof(binding_key_id)='text'
      AND instr(binding_key_id,char(0)) IS 0
      AND length(CAST(binding_key_id AS BLOB)) BETWEEN 1 AND 64
      AND substr(binding_key_id,1,1) GLOB '[A-Za-z0-9]'
      AND substr(binding_key_id,2) NOT GLOB '*[^A-Za-z0-9._-]*'
    THEN 1 ELSE 0 END = 1
      AND typeof(binding_key_fingerprint)='blob' AND length(binding_key_fingerprint)=32
      AND CASE WHEN typeof(envelope_key_id)='text'
      AND instr(envelope_key_id,char(0)) IS 0
      AND length(CAST(envelope_key_id AS BLOB)) BETWEEN 1 AND 64
      AND substr(envelope_key_id,1,1) GLOB '[A-Za-z0-9]'
      AND substr(envelope_key_id,2) NOT GLOB '*[^A-Za-z0-9._-]*'
    THEN 1 ELSE 0 END = 1
      AND typeof(envelope_key_fingerprint)='blob' AND length(envelope_key_fingerprint)=32)
  ),
  CHECK (codec_version != 3 OR (
    phase_tag = 1 AND revision = 1 AND run_ref IS NULL AND receipt_ref IS NULL
    AND assigned_at_unix_ns IS NULL AND effect_intent_ref IS NULL
    AND effect_intent_at_unix_ns IS NULL AND staging_ref IS NULL
    AND staging_at_unix_ns IS NULL AND dispatch_ref IS NULL
    AND dispatch_at_unix_ns IS NULL AND provider_observation_kind = 0
    AND provider_observation_ref IS NULL AND provider_observation_at_unix_ns IS NULL
    AND reconciliation_kind = 0 AND reconciliation_ref IS NULL
    AND reconciliation_at_unix_ns IS NULL AND retention_state = 1
    AND unavailable_at_unix_ns IS NULL AND unavailable_reason = ''
    AND expires_at_unix_ns IS NULL AND latest_operation_kind = 1
  )),
  CHECK (codec_version != 4 OR (
    retention_state = 1 AND expires_at_unix_ns IS NULL
    AND unavailable_at_unix_ns IS NULL AND unavailable_reason = ''
    AND binding_key_id <> envelope_key_id AND binding_key_fingerprint <> envelope_key_fingerprint
    AND length(last_mutation_ref) = 32
    AND ((revision = 1 AND latest_operation_kind = 1 AND phase_tag IN (1,2)
        AND updated_at_unix_ns = created_at_unix_ns)
      OR (revision > 1 AND latest_operation_kind BETWEEN 2 AND 9))
    AND (provider_observation_kind = 0 OR provider_observation_at_unix_ns >= dispatch_at_unix_ns)
    AND (run_ref IS NULL OR length(run_ref) = 32)
    AND (receipt_ref IS NULL OR length(receipt_ref) = 32)
    AND (effect_intent_ref IS NULL OR length(effect_intent_ref) = 32)
    AND (staging_ref IS NULL OR length(staging_ref) = 32)
    AND (dispatch_ref IS NULL OR length(dispatch_ref) = 32)
    AND (provider_observation_ref IS NULL OR length(provider_observation_ref) = 32)
    AND (reconciliation_ref IS NULL OR length(reconciliation_ref) = 32)
    AND (assigned_at_unix_ns IS NULL OR assigned_at_unix_ns BETWEEN created_at_unix_ns AND updated_at_unix_ns)
    AND (effect_intent_at_unix_ns IS NULL OR effect_intent_at_unix_ns BETWEEN created_at_unix_ns AND updated_at_unix_ns)
    AND (staging_at_unix_ns IS NULL OR staging_at_unix_ns BETWEEN created_at_unix_ns AND updated_at_unix_ns)
    AND (dispatch_at_unix_ns IS NULL OR dispatch_at_unix_ns BETWEEN created_at_unix_ns AND updated_at_unix_ns)
    AND (provider_observation_at_unix_ns IS NULL OR provider_observation_at_unix_ns BETWEEN created_at_unix_ns AND updated_at_unix_ns)
    AND (reconciliation_at_unix_ns IS NULL OR reconciliation_at_unix_ns BETWEEN created_at_unix_ns AND updated_at_unix_ns)
  )),
  CHECK (codec_version != 5 OR (
    retention_state = 1 AND expires_at_unix_ns IS NULL
    AND unavailable_at_unix_ns IS NULL AND unavailable_reason = ''
    AND binding_key_id <> envelope_key_id AND binding_key_fingerprint <> envelope_key_fingerprint
    AND length(last_mutation_ref) = 32 AND last_mutation_ref <> zeroblob(32)
    AND reconciliation_kind = 0 AND provider_observation_kind IN (0,3)
    AND (run_ref IS NULL OR (
      length(run_ref) = 69 AND instr(run_ref, x'00') = 0
      AND substr(CAST(run_ref AS TEXT),1,5) = 'esoh-' COLLATE BINARY
      AND substr(CAST(run_ref AS TEXT),6) NOT GLOB '*[^a-f0-9]*'
      AND substr(CAST(run_ref AS TEXT),6) <> '0000000000000000000000000000000000000000000000000000000000000000'
    ))
    AND (receipt_ref IS NULL OR length(receipt_ref) = 32 AND receipt_ref <> zeroblob(32))
    AND (effect_intent_ref IS NULL OR length(effect_intent_ref) = 32 AND effect_intent_ref <> zeroblob(32))
    AND (staging_ref IS NULL OR length(staging_ref) = 32 AND staging_ref <> zeroblob(32))
    AND (dispatch_ref IS NULL OR length(dispatch_ref) = 32 AND dispatch_ref <> zeroblob(32))
    AND (provider_observation_ref IS NULL OR length(provider_observation_ref) = 32 AND provider_observation_ref <> zeroblob(32))
    AND (assigned_at_unix_ns IS NULL OR assigned_at_unix_ns BETWEEN created_at_unix_ns AND updated_at_unix_ns)
    AND (effect_intent_at_unix_ns IS NULL OR effect_intent_at_unix_ns BETWEEN assigned_at_unix_ns AND updated_at_unix_ns)
    AND (staging_at_unix_ns IS NULL OR staging_at_unix_ns BETWEEN effect_intent_at_unix_ns AND updated_at_unix_ns)
    AND (dispatch_at_unix_ns IS NULL OR dispatch_at_unix_ns BETWEEN staging_at_unix_ns AND updated_at_unix_ns)
    AND (provider_observation_at_unix_ns IS NULL OR provider_observation_at_unix_ns BETWEEN dispatch_at_unix_ns AND updated_at_unix_ns)
    AND (
      (revision = 1 AND latest_operation_kind = 1 AND phase_tag = 1
        AND updated_at_unix_ns = created_at_unix_ns
        AND run_ref IS NULL AND effect_intent_ref IS NULL)
      OR (revision = 2 AND latest_operation_kind = 2 AND phase_tag = 3
        AND assigned_at_unix_ns IS updated_at_unix_ns AND effect_intent_ref IS NULL)
      OR (revision = 3 AND latest_operation_kind = 3 AND phase_tag = 3
        AND effect_intent_at_unix_ns IS updated_at_unix_ns AND staging_ref IS NULL)
      OR (revision = 4 AND latest_operation_kind = 4 AND phase_tag = 3
        AND staging_at_unix_ns IS updated_at_unix_ns AND dispatch_ref IS NULL)
      OR (revision = 5 AND latest_operation_kind = 5 AND phase_tag = 3
        AND staging_ref IS NOT NULL AND dispatch_at_unix_ns IS updated_at_unix_ns)
      OR (revision = 6 AND latest_operation_kind = 8 AND phase_tag = 6
        AND staging_ref IS NOT NULL AND provider_observation_at_unix_ns IS updated_at_unix_ns)
    )
  ))
) STRICT;
INSERT INTO reliable_submit_claims (claim_rowid, caller_ref, submit_key_ref, plan_binding, witness_resolved_mask, witness_inapplicable_mask, phase_tag, run_ref, receipt_ref, revision, created_at_unix_ns, updated_at_unix_ns, assigned_at_unix_ns, effect_intent_ref, effect_intent_at_unix_ns, staging_ref, staging_at_unix_ns, dispatch_ref, dispatch_at_unix_ns, provider_observation_kind, provider_observation_ref, provider_observation_at_unix_ns, reconciliation_kind, reconciliation_ref, reconciliation_at_unix_ns, expires_at_unix_ns, retention_state, unavailable_at_unix_ns, unavailable_reason, last_mutation_ref, latest_operation_kind, latest_operation_input_digest, codec_version, replay_scope, intent_format, intent_commitment, context_commitment, envelope_wrapper_format, envelope_payload_format, envelope_algorithm, envelope_ref, envelope_size, envelope_sha256, binding_key_id, binding_key_fingerprint, envelope_key_id, envelope_key_fingerprint)
SELECT claim_rowid, caller_ref, submit_key_ref, plan_binding, witness_resolved_mask, witness_inapplicable_mask, phase_tag, run_ref, receipt_ref, revision, created_at_unix_ns, updated_at_unix_ns, assigned_at_unix_ns, effect_intent_ref, effect_intent_at_unix_ns, staging_ref, staging_at_unix_ns, dispatch_ref, dispatch_at_unix_ns, provider_observation_kind, provider_observation_ref, provider_observation_at_unix_ns, reconciliation_kind, reconciliation_ref, reconciliation_at_unix_ns, expires_at_unix_ns, retention_state, unavailable_at_unix_ns, unavailable_reason, last_mutation_ref, latest_operation_kind, latest_operation_input_digest, codec_version, replay_scope, intent_format, intent_commitment, context_commitment, envelope_wrapper_format, envelope_payload_format, envelope_algorithm, envelope_ref, envelope_size, envelope_sha256, binding_key_id, binding_key_fingerprint, envelope_key_id, envelope_key_fingerprint FROM reliable_submit_claims_v4;
CREATE TEMP TABLE replay_m5_assert (ok INTEGER NOT NULL CHECK (ok=1)) STRICT;
INSERT INTO replay_m5_assert(ok)
SELECT CASE WHEN
  (SELECT count(*) FROM replay_m5_key_before) = (SELECT count(*) FROM reliable_submit_key_registry)
  AND NOT EXISTS (SELECT rowid, key_id COLLATE BINARY, purpose, material_fingerprint, state FROM replay_m5_key_before EXCEPT SELECT rowid, key_id COLLATE BINARY, purpose, material_fingerprint, state FROM reliable_submit_key_registry)
  AND NOT EXISTS (SELECT rowid, key_id COLLATE BINARY, purpose, material_fingerprint, state FROM reliable_submit_key_registry EXCEPT SELECT rowid, key_id COLLATE BINARY, purpose, material_fingerprint, state FROM replay_m5_key_before)
  AND (SELECT count(*) FROM replay_m5_grant_before) = (SELECT count(*) FROM reliable_submit_seal_use)
  AND NOT EXISTS (SELECT rowid, envelope_key_id COLLATE BINARY, granted_count FROM replay_m5_grant_before EXCEPT SELECT rowid, envelope_key_id COLLATE BINARY, granted_count FROM reliable_submit_seal_use)
  AND NOT EXISTS (SELECT rowid, envelope_key_id COLLATE BINARY, granted_count FROM reliable_submit_seal_use EXCEPT SELECT rowid, envelope_key_id COLLATE BINARY, granted_count FROM replay_m5_grant_before)
  AND (SELECT count(*) FROM replay_m5_ledger_before) = (SELECT count(*) FROM reliable_submit_migrations)
  AND NOT EXISTS (SELECT version, name COLLATE BINARY, applied_at_unix_ns, source_sha256 COLLATE BINARY FROM replay_m5_ledger_before EXCEPT SELECT version, name COLLATE BINARY, applied_at_unix_ns, source_sha256 COLLATE BINARY FROM reliable_submit_migrations)
  AND NOT EXISTS (SELECT version, name COLLATE BINARY, applied_at_unix_ns, source_sha256 COLLATE BINARY FROM reliable_submit_migrations EXCEPT SELECT version, name COLLATE BINARY, applied_at_unix_ns, source_sha256 COLLATE BINARY FROM replay_m5_ledger_before)
  AND (SELECT count(*) FROM reliable_submit_claims_v4) = (SELECT count(*) FROM reliable_submit_claims)
  AND NOT EXISTS (SELECT claim_rowid, caller_ref, submit_key_ref, plan_binding, witness_resolved_mask, witness_inapplicable_mask, phase_tag, run_ref, receipt_ref, revision, created_at_unix_ns, updated_at_unix_ns, assigned_at_unix_ns, effect_intent_ref, effect_intent_at_unix_ns, staging_ref, staging_at_unix_ns, dispatch_ref, dispatch_at_unix_ns, provider_observation_kind, provider_observation_ref, provider_observation_at_unix_ns, reconciliation_kind, reconciliation_ref, reconciliation_at_unix_ns, expires_at_unix_ns, retention_state, unavailable_at_unix_ns, unavailable_reason COLLATE BINARY, last_mutation_ref, latest_operation_kind, latest_operation_input_digest, codec_version, replay_scope, intent_format, intent_commitment, context_commitment, envelope_wrapper_format, envelope_payload_format, envelope_algorithm, envelope_ref COLLATE BINARY, envelope_size, envelope_sha256, binding_key_id COLLATE BINARY, binding_key_fingerprint, envelope_key_id COLLATE BINARY, envelope_key_fingerprint FROM reliable_submit_claims_v4
    EXCEPT SELECT claim_rowid, caller_ref, submit_key_ref, plan_binding, witness_resolved_mask, witness_inapplicable_mask, phase_tag, run_ref, receipt_ref, revision, created_at_unix_ns, updated_at_unix_ns, assigned_at_unix_ns, effect_intent_ref, effect_intent_at_unix_ns, staging_ref, staging_at_unix_ns, dispatch_ref, dispatch_at_unix_ns, provider_observation_kind, provider_observation_ref, provider_observation_at_unix_ns, reconciliation_kind, reconciliation_ref, reconciliation_at_unix_ns, expires_at_unix_ns, retention_state, unavailable_at_unix_ns, unavailable_reason COLLATE BINARY, last_mutation_ref, latest_operation_kind, latest_operation_input_digest, codec_version, replay_scope, intent_format, intent_commitment, context_commitment, envelope_wrapper_format, envelope_payload_format, envelope_algorithm, envelope_ref COLLATE BINARY, envelope_size, envelope_sha256, binding_key_id COLLATE BINARY, binding_key_fingerprint, envelope_key_id COLLATE BINARY, envelope_key_fingerprint FROM reliable_submit_claims)
  AND NOT EXISTS (SELECT claim_rowid, caller_ref, submit_key_ref, plan_binding, witness_resolved_mask, witness_inapplicable_mask, phase_tag, run_ref, receipt_ref, revision, created_at_unix_ns, updated_at_unix_ns, assigned_at_unix_ns, effect_intent_ref, effect_intent_at_unix_ns, staging_ref, staging_at_unix_ns, dispatch_ref, dispatch_at_unix_ns, provider_observation_kind, provider_observation_ref, provider_observation_at_unix_ns, reconciliation_kind, reconciliation_ref, reconciliation_at_unix_ns, expires_at_unix_ns, retention_state, unavailable_at_unix_ns, unavailable_reason COLLATE BINARY, last_mutation_ref, latest_operation_kind, latest_operation_input_digest, codec_version, replay_scope, intent_format, intent_commitment, context_commitment, envelope_wrapper_format, envelope_payload_format, envelope_algorithm, envelope_ref COLLATE BINARY, envelope_size, envelope_sha256, binding_key_id COLLATE BINARY, binding_key_fingerprint, envelope_key_id COLLATE BINARY, envelope_key_fingerprint FROM reliable_submit_claims
    EXCEPT SELECT claim_rowid, caller_ref, submit_key_ref, plan_binding, witness_resolved_mask, witness_inapplicable_mask, phase_tag, run_ref, receipt_ref, revision, created_at_unix_ns, updated_at_unix_ns, assigned_at_unix_ns, effect_intent_ref, effect_intent_at_unix_ns, staging_ref, staging_at_unix_ns, dispatch_ref, dispatch_at_unix_ns, provider_observation_kind, provider_observation_ref, provider_observation_at_unix_ns, reconciliation_kind, reconciliation_ref, reconciliation_at_unix_ns, expires_at_unix_ns, retention_state, unavailable_at_unix_ns, unavailable_reason COLLATE BINARY, last_mutation_ref, latest_operation_kind, latest_operation_input_digest, codec_version, replay_scope, intent_format, intent_commitment, context_commitment, envelope_wrapper_format, envelope_payload_format, envelope_algorithm, envelope_ref COLLATE BINARY, envelope_size, envelope_sha256, binding_key_id COLLATE BINARY, binding_key_fingerprint, envelope_key_id COLLATE BINARY, envelope_key_fingerprint FROM reliable_submit_claims_v4)
  THEN 1 ELSE 0 END;
DROP TABLE replay_m5_assert;
DROP TABLE replay_m5_key_before;
DROP TABLE replay_m5_grant_before;
DROP TABLE replay_m5_ledger_before;
DROP TABLE reliable_submit_claims_v4;
CREATE UNIQUE INDEX reliable_submit_claims_envelope_ref_unique
ON reliable_submit_claims(envelope_ref);
CREATE UNIQUE INDEX reliable_submit_operational_run_ref_unique
ON reliable_submit_claims(run_ref COLLATE BINARY) WHERE codec_version = 5 AND run_ref IS NOT NULL;
CREATE TABLE reliable_submit_operational_admission (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  installation BLOB NOT NULL CHECK (length(installation) = 32 AND installation != zeroblob(32)),
  epoch INTEGER NOT NULL CHECK (epoch > 0),
  generation INTEGER NOT NULL CHECK (generation > 0),
  admission_digest BLOB NOT NULL CHECK (length(admission_digest) = 32),
  state INTEGER NOT NULL CHECK (state IN (1, 2)),
  updated_at_unix_ns INTEGER NOT NULL CHECK (updated_at_unix_ns > 0)
) STRICT;
CREATE TRIGGER reliable_submit_operational_admission_no_delete
BEFORE DELETE ON reliable_submit_operational_admission
BEGIN SELECT RAISE(ABORT, 'operational admission deletion is forbidden'); END;
CREATE TRIGGER reliable_submit_operational_admission_guard_insert
BEFORE INSERT ON reliable_submit_operational_admission
BEGIN
  SELECT CASE WHEN EXISTS (SELECT 1 FROM reliable_submit_operational_admission)
    OR NEW.singleton IS NOT 1
    OR NEW.generation IS NOT 1
    OR NEW.state IS NOT 1
    THEN RAISE(ABORT, 'invalid operational admission commission') END;
END;
CREATE TRIGGER reliable_submit_operational_admission_guard_update
BEFORE UPDATE ON reliable_submit_operational_admission
BEGIN
  SELECT CASE WHEN NEW.singleton IS NOT OLD.singleton
    OR NEW.installation IS NOT OLD.installation
    OR NEW.epoch IS NOT OLD.epoch
    THEN RAISE(ABORT, 'immutable operational admission identity') END;
  SELECT CASE WHEN NEW.updated_at_unix_ns < OLD.updated_at_unix_ns
    THEN RAISE(ABORT, 'operational admission time regression') END;
  SELECT CASE WHEN NOT (
      (NEW.generation IS OLD.generation
        AND NEW.admission_digest IS OLD.admission_digest
        AND OLD.state = 1 AND NEW.state = 2)
      OR (NEW.generation IS OLD.generation + 1
        AND NEW.admission_digest IS NOT OLD.admission_digest
        AND NEW.state = 1))
    THEN RAISE(ABORT, 'invalid operational admission transition') END;
END;
CREATE TRIGGER reliable_submit_claims_no_delete
BEFORE DELETE ON reliable_submit_claims
BEGIN SELECT RAISE(ABORT, 'reliable submit claim deletion is forbidden'); END;
CREATE TRIGGER reliable_submit_claims_guard_insert_v5
BEFORE INSERT ON reliable_submit_claims
BEGIN
  SELECT CASE WHEN NEW.codec_version NOT IN (3,4,5) THEN RAISE(ABORT, 'new claim requires custody codec') END;
  SELECT CASE WHEN NEW.revision IS NOT 1 OR (NEW.codec_version = 3 AND NEW.phase_tag IS NOT 1)
    OR (NEW.codec_version = 4 AND NEW.phase_tag NOT IN (1,2))
    OR NEW.latest_operation_kind IS NOT 1 THEN RAISE(ABORT, 'invalid custody initial shape') END;
  SELECT CASE WHEN NEW.codec_version = 5 AND NOT EXISTS (
    SELECT 1 FROM reliable_submit_operational_admission AS a WHERE a.state = 1)
    THEN RAISE(ABORT, 'operational admission unavailable') END;
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM reliable_submit_key_registry AS r
    WHERE (r.key_id COLLATE BINARY)=NEW.binding_key_id
      AND r.purpose=1 AND r.state=1
      AND r.material_fingerprint=NEW.binding_key_fingerprint)
    THEN RAISE(ABORT, 'binding key unavailable') END;
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM reliable_submit_key_registry AS r
    WHERE (r.key_id COLLATE BINARY)=NEW.envelope_key_id
      AND r.purpose=2 AND r.state=1
      AND r.material_fingerprint=NEW.envelope_key_fingerprint)
    THEN RAISE(ABORT, 'envelope key unavailable') END;
END;
CREATE TRIGGER reliable_submit_claims_guard_update
BEFORE UPDATE ON reliable_submit_claims
BEGIN
  SELECT CASE WHEN OLD.codec_version NOT IN (4,5) AND (NEW.replay_scope IS NOT NULL OR NEW.intent_format IS NOT NULL OR NEW.intent_commitment IS NOT NULL OR NEW.context_commitment IS NOT NULL OR NEW.envelope_wrapper_format IS NOT NULL OR NEW.envelope_payload_format IS NOT NULL OR NEW.envelope_algorithm IS NOT NULL OR NEW.envelope_ref IS NOT NULL OR NEW.envelope_size IS NOT NULL OR NEW.envelope_sha256 IS NOT NULL OR NEW.binding_key_id IS NOT NULL OR NEW.binding_key_fingerprint IS NOT NULL OR NEW.envelope_key_id IS NOT NULL OR NEW.envelope_key_fingerprint IS NOT NULL) THEN RAISE(ABORT, 'legacy custody fields must remain NULL') END;
  SELECT CASE WHEN OLD.codec_version NOT IN (4,5) AND (OLD.codec_version = 3) THEN RAISE(ABORT, 'immutable synthetic claim') END;
  SELECT CASE WHEN OLD.codec_version NOT IN (4,5) AND (NEW.caller_ref IS NOT OLD.caller_ref) THEN RAISE(ABORT, 'immutable caller reference') END;
  SELECT CASE WHEN OLD.codec_version NOT IN (4,5) AND (NEW.submit_key_ref IS NOT OLD.submit_key_ref) THEN RAISE(ABORT, 'immutable submit key reference') END;
  SELECT CASE WHEN OLD.codec_version NOT IN (4,5) AND (NEW.plan_binding IS NOT OLD.plan_binding) THEN RAISE(ABORT, 'immutable plan binding') END;
  SELECT CASE WHEN OLD.codec_version NOT IN (4,5) AND (NEW.witness_resolved_mask IS NOT OLD.witness_resolved_mask) THEN RAISE(ABORT, 'immutable witness') END;
  SELECT CASE WHEN OLD.codec_version NOT IN (4,5) AND (NEW.witness_inapplicable_mask IS NOT OLD.witness_inapplicable_mask) THEN RAISE(ABORT, 'immutable witness') END;
  SELECT CASE WHEN OLD.codec_version NOT IN (4,5) AND (NEW.created_at_unix_ns IS NOT OLD.created_at_unix_ns) THEN RAISE(ABORT, 'immutable creation time') END;
  SELECT CASE WHEN OLD.codec_version NOT IN (4,5) AND (NOT ((OLD.codec_version = 1 AND NEW.codec_version = 2) OR (OLD.codec_version = 2 AND NEW.codec_version = 2))) THEN RAISE(ABORT, 'codec version can only advance to v2') END;
  SELECT CASE WHEN OLD.codec_version NOT IN (4,5) AND (NEW.revision != OLD.revision + 1) THEN RAISE(ABORT, 'revision must increment by one') END;
  SELECT CASE WHEN OLD.codec_version NOT IN (4,5) AND (NEW.last_mutation_ref = OLD.last_mutation_ref) THEN RAISE(ABORT, 'mutation reference must change with revision') END;
  SELECT CASE WHEN OLD.codec_version NOT IN (4,5) AND (NEW.latest_operation_kind IS NULL) THEN RAISE(ABORT, 'latest operation kind is required') END;
  SELECT CASE WHEN OLD.codec_version NOT IN (4,5) AND (NEW.latest_operation_input_digest IS NULL) THEN RAISE(ABORT, 'latest operation input digest is required') END;
  SELECT CASE WHEN OLD.codec_version NOT IN (4,5) AND (OLD.run_ref IS NOT NULL AND (NEW.run_ref IS NULL OR NEW.run_ref IS NOT OLD.run_ref)) THEN RAISE(ABORT, 'immutable run reference') END;
  SELECT CASE WHEN OLD.codec_version NOT IN (4,5) AND (OLD.receipt_ref IS NOT NULL AND (NEW.receipt_ref IS NULL OR NEW.receipt_ref IS NOT OLD.receipt_ref)) THEN RAISE(ABORT, 'immutable receipt reference') END;
  SELECT CASE WHEN OLD.codec_version NOT IN (4,5) AND (OLD.phase_tag IN (6, 7) AND NEW.phase_tag != OLD.phase_tag) THEN RAISE(ABORT, 'terminal phase is immutable') END;
  SELECT CASE WHEN OLD.codec_version NOT IN (4,5) AND (OLD.retention_state != 1 AND NEW.retention_state = 1) THEN RAISE(ABORT, 'inactive claim cannot become active') END;
  SELECT CASE WHEN OLD.codec_version IN (4,5) AND (
    NEW.claim_rowid IS NOT OLD.claim_rowid OR
    NEW.caller_ref IS NOT OLD.caller_ref OR
    NEW.submit_key_ref IS NOT OLD.submit_key_ref OR
    NEW.plan_binding IS NOT OLD.plan_binding OR
    NEW.witness_resolved_mask IS NOT OLD.witness_resolved_mask OR
    NEW.witness_inapplicable_mask IS NOT OLD.witness_inapplicable_mask OR
    NEW.created_at_unix_ns IS NOT OLD.created_at_unix_ns OR
    NEW.expires_at_unix_ns IS NOT OLD.expires_at_unix_ns OR
    NEW.retention_state IS NOT OLD.retention_state OR
    NEW.unavailable_at_unix_ns IS NOT OLD.unavailable_at_unix_ns OR
    NEW.unavailable_reason IS NOT OLD.unavailable_reason OR
    NEW.codec_version IS NOT OLD.codec_version OR
    NEW.replay_scope IS NOT OLD.replay_scope OR
    NEW.intent_format IS NOT OLD.intent_format OR
    NEW.intent_commitment IS NOT OLD.intent_commitment OR
    NEW.context_commitment IS NOT OLD.context_commitment OR
    NEW.envelope_wrapper_format IS NOT OLD.envelope_wrapper_format OR
    NEW.envelope_payload_format IS NOT OLD.envelope_payload_format OR
    NEW.envelope_algorithm IS NOT OLD.envelope_algorithm OR
    NEW.envelope_ref IS NOT OLD.envelope_ref OR
    NEW.envelope_size IS NOT OLD.envelope_size OR
    NEW.envelope_sha256 IS NOT OLD.envelope_sha256 OR
    NEW.binding_key_id IS NOT OLD.binding_key_id OR
    NEW.binding_key_fingerprint IS NOT OLD.binding_key_fingerprint OR
    NEW.envelope_key_id IS NOT OLD.envelope_key_id OR
    NEW.envelope_key_fingerprint IS NOT OLD.envelope_key_fingerprint)
    THEN RAISE(ABORT, 'immutable progress original') END;
  SELECT CASE WHEN OLD.codec_version = 4 AND (
    NEW.revision != OLD.revision + 1 OR NEW.updated_at_unix_ns < OLD.updated_at_unix_ns
    OR NEW.last_mutation_ref IS OLD.last_mutation_ref
    OR (OLD.phase_tag IN (6,7) AND NEW.phase_tag IS NOT OLD.phase_tag))
    THEN RAISE(ABORT, 'invalid progress revision or terminal state') END;
  SELECT CASE WHEN OLD.codec_version = 4 AND (
    (NEW.phase_tag IS NOT OLD.phase_tag AND NEW.latest_operation_kind NOT IN (2,6,7,8,9)) OR
    (NEW.run_ref IS NOT OLD.run_ref AND NEW.latest_operation_kind NOT IN (2)) OR
    (NEW.assigned_at_unix_ns IS NOT OLD.assigned_at_unix_ns AND NEW.latest_operation_kind NOT IN (2)) OR
    (NEW.receipt_ref IS NOT OLD.receipt_ref AND NEW.latest_operation_kind NOT IN (8)) OR
    (NEW.effect_intent_ref IS NOT OLD.effect_intent_ref AND NEW.latest_operation_kind NOT IN (3)) OR
    (NEW.effect_intent_at_unix_ns IS NOT OLD.effect_intent_at_unix_ns AND NEW.latest_operation_kind NOT IN (3)) OR
    (NEW.staging_ref IS NOT OLD.staging_ref AND NEW.latest_operation_kind NOT IN (4)) OR
    (NEW.staging_at_unix_ns IS NOT OLD.staging_at_unix_ns AND NEW.latest_operation_kind NOT IN (4)) OR
    (NEW.dispatch_ref IS NOT OLD.dispatch_ref AND NEW.latest_operation_kind NOT IN (5)) OR
    (NEW.dispatch_at_unix_ns IS NOT OLD.dispatch_at_unix_ns AND NEW.latest_operation_kind NOT IN (5)) OR
    (NEW.provider_observation_kind IS NOT OLD.provider_observation_kind AND NEW.latest_operation_kind NOT IN (6,8,9)) OR
    (NEW.provider_observation_ref IS NOT OLD.provider_observation_ref AND NEW.latest_operation_kind NOT IN (6,8,9)) OR
    (NEW.provider_observation_at_unix_ns IS NOT OLD.provider_observation_at_unix_ns AND NEW.latest_operation_kind NOT IN (6,8,9)) OR
    (NEW.reconciliation_kind IS NOT OLD.reconciliation_kind AND NEW.latest_operation_kind NOT IN (7)) OR
    (NEW.reconciliation_ref IS NOT OLD.reconciliation_ref AND NEW.latest_operation_kind NOT IN (7)) OR
    (NEW.reconciliation_at_unix_ns IS NOT OLD.reconciliation_at_unix_ns AND NEW.latest_operation_kind NOT IN (7)))
    THEN RAISE(ABORT, 'invalid progress column update') END;
  SELECT CASE WHEN OLD.codec_version = 4 AND (
    (NEW.latest_operation_kind = 2 AND (OLD.run_ref IS NOT NULL OR NEW.run_ref IS NULL OR NEW.phase_tag != 3)) OR
    (NEW.latest_operation_kind = 3 AND (OLD.effect_intent_ref IS NOT NULL OR NEW.effect_intent_ref IS NULL)) OR
    (NEW.latest_operation_kind = 4 AND (OLD.staging_ref IS NOT NULL OR NEW.staging_ref IS NULL)) OR
    (NEW.latest_operation_kind = 5 AND (OLD.dispatch_ref IS NOT NULL OR NEW.dispatch_ref IS NULL)) OR
    (NEW.latest_operation_kind = 7 AND (OLD.reconciliation_ref IS NOT NULL OR NEW.reconciliation_ref IS NULL))
    OR (NEW.latest_operation_kind = 6 AND (OLD.provider_observation_kind != 0
      OR NEW.provider_observation_kind NOT IN (1,2,5)))
    OR (NEW.latest_operation_kind = 8 AND (OLD.phase_tag NOT IN (3,4,5)
      OR NEW.provider_observation_kind != 3 OR NEW.receipt_ref IS NULL))
    OR (NEW.latest_operation_kind = 9 AND (OLD.phase_tag NOT IN (3,4,5)
      OR NEW.provider_observation_kind != 4))
    OR (NEW.latest_operation_kind = 5 AND (OLD.phase_tag != 3 OR OLD.provider_observation_kind != 0))
    OR (NEW.latest_operation_kind = 7 AND (
        (NEW.reconciliation_kind = 1 AND (OLD.phase_tag != 3 OR OLD.dispatch_ref IS NOT NULL))
        OR (NEW.reconciliation_kind = 2 AND NEW.phase_tag != 4)
        OR (NEW.reconciliation_kind IN (3,6) AND NEW.phase_tag != 5))))
    THEN RAISE(ABORT, 'invalid progress fact update') END;
  SELECT CASE WHEN OLD.codec_version = 4 AND (
    NOT EXISTS (SELECT 1 FROM reliable_submit_key_registry
      WHERE key_id = NEW.binding_key_id COLLATE BINARY AND purpose = 1
        AND state IN (1,2) AND material_fingerprint = NEW.binding_key_fingerprint))
    THEN RAISE(ABORT, 'binding key unavailable') END;
  SELECT CASE WHEN OLD.codec_version = 4 AND (
    NOT EXISTS (SELECT 1 FROM reliable_submit_key_registry
      WHERE key_id = NEW.envelope_key_id COLLATE BINARY AND purpose = 2
        AND state IN (1,2) AND material_fingerprint = NEW.envelope_key_fingerprint))
    THEN RAISE(ABORT, 'envelope key unavailable') END;
END;

CREATE TRIGGER reliable_submit_claims_guard_operational_update
BEFORE UPDATE ON reliable_submit_claims
WHEN OLD.codec_version = 5
BEGIN
  SELECT CASE WHEN NEW.revision != OLD.revision + 1
    OR NEW.updated_at_unix_ns < OLD.updated_at_unix_ns
    OR NEW.last_mutation_ref IS OLD.last_mutation_ref
    OR OLD.phase_tag = 6
    THEN RAISE(ABORT, 'invalid operational progress') END;
  SELECT CASE WHEN (OLD.run_ref IS NOT NULL AND
    (NEW.run_ref IS NOT OLD.run_ref OR NEW.assigned_at_unix_ns IS NOT OLD.assigned_at_unix_ns))
    OR (OLD.effect_intent_ref IS NOT NULL AND
      (NEW.effect_intent_ref IS NOT OLD.effect_intent_ref OR NEW.effect_intent_at_unix_ns IS NOT OLD.effect_intent_at_unix_ns))
    OR (OLD.staging_ref IS NOT NULL AND
      (NEW.staging_ref IS NOT OLD.staging_ref OR NEW.staging_at_unix_ns IS NOT OLD.staging_at_unix_ns))
    OR (OLD.dispatch_ref IS NOT NULL AND
      (NEW.dispatch_ref IS NOT OLD.dispatch_ref OR NEW.dispatch_at_unix_ns IS NOT OLD.dispatch_at_unix_ns))
    THEN RAISE(ABORT, 'immutable operational progress') END;
  SELECT CASE WHEN NEW.latest_operation_kind IS NOT 8 AND NOT EXISTS (
      SELECT 1 FROM reliable_submit_operational_admission AS a WHERE a.state = 1)
    THEN RAISE(ABORT, 'operational admission unavailable') END;
  SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM reliable_submit_key_registry
      WHERE key_id = NEW.binding_key_id COLLATE BINARY AND purpose = 1
        AND (state = 1 OR state = 2 AND NEW.latest_operation_kind = 8)
        AND material_fingerprint = NEW.binding_key_fingerprint)
    THEN RAISE(ABORT, 'operational binding key unavailable') END;
  SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM reliable_submit_key_registry
      WHERE key_id = NEW.envelope_key_id COLLATE BINARY AND purpose = 2
        AND (state = 1 OR state = 2 AND NEW.latest_operation_kind = 8)
        AND material_fingerprint = NEW.envelope_key_fingerprint)
    THEN RAISE(ABORT, 'operational envelope key unavailable') END;
END;
`
