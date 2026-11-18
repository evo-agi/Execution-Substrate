package reliablesubmit

// sqliteMigration3SQL is the complete atomic schema-3 migration literal.
const sqliteMigration3SQL = `
CREATE TABLE reliable_submit_key_registry (
  key_id TEXT PRIMARY KEY CHECK (CASE WHEN typeof(key_id)='text'
      AND instr(key_id,char(0)) IS 0
      AND length(CAST(key_id AS BLOB)) BETWEEN 1 AND 64
      AND substr(key_id,1,1) GLOB '[A-Za-z0-9]'
      AND substr(key_id,2) NOT GLOB '*[^A-Za-z0-9._-]*'
    THEN 1 ELSE 0 END = 1),
  purpose INTEGER NOT NULL CHECK (purpose IN (1,2)),
  material_fingerprint BLOB NOT NULL UNIQUE CHECK (length(material_fingerprint)=32),
  state INTEGER NOT NULL CHECK (state IN (1,2,3))
) STRICT;
CREATE TABLE reliable_submit_seal_use (
  envelope_key_id TEXT PRIMARY KEY REFERENCES reliable_submit_key_registry(key_id)
    CHECK (CASE WHEN typeof(envelope_key_id)='text'
      AND instr(envelope_key_id,char(0)) IS 0
      AND length(CAST(envelope_key_id AS BLOB)) BETWEEN 1 AND 64
      AND substr(envelope_key_id,1,1) GLOB '[A-Za-z0-9]'
      AND substr(envelope_key_id,2) NOT GLOB '*[^A-Za-z0-9._-]*'
    THEN 1 ELSE 0 END = 1),
  granted_count INTEGER NOT NULL CHECK (granted_count BETWEEN 0 AND 4294967296)
) STRICT;
DROP TRIGGER reliable_submit_claims_no_delete;
DROP TRIGGER reliable_submit_claims_guard_insert_v2;
DROP TRIGGER reliable_submit_claims_guard_update;
ALTER TABLE reliable_submit_claims RENAME TO reliable_submit_claims_v2;
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
  codec_version INTEGER NOT NULL CHECK (codec_version IN (1, 2, 3)),

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
    (codec_version IN (2, 3) AND latest_operation_kind IS NOT NULL AND latest_operation_input_digest IS NOT NULL)
  ),
  CHECK (
    (codec_version IN (1, 2) AND replay_scope IS NULL AND intent_format IS NULL AND intent_commitment IS NULL AND context_commitment IS NULL AND envelope_wrapper_format IS NULL AND envelope_payload_format IS NULL AND envelope_algorithm IS NULL AND envelope_ref IS NULL AND envelope_size IS NULL AND envelope_sha256 IS NULL AND binding_key_id IS NULL AND binding_key_fingerprint IS NULL AND envelope_key_id IS NULL AND envelope_key_fingerprint IS NULL)
    OR (codec_version = 3
      AND length(caller_ref) = 32
      AND length(submit_key_ref) = 32
      AND length(plan_binding) BETWEEN 1 AND 256
      AND replay_scope IS 1
      AND intent_format IS 1
      AND typeof(intent_commitment)='blob' AND length(intent_commitment)=32
      AND typeof(context_commitment)='blob' AND length(context_commitment)=32
      AND envelope_wrapper_format IS 1
      AND envelope_payload_format IS 1
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
  ))
) STRICT;
INSERT INTO reliable_submit_claims (claim_rowid, caller_ref, submit_key_ref, plan_binding, witness_resolved_mask, witness_inapplicable_mask, phase_tag, run_ref, receipt_ref, revision, created_at_unix_ns, updated_at_unix_ns, assigned_at_unix_ns, effect_intent_ref, effect_intent_at_unix_ns, staging_ref, staging_at_unix_ns, dispatch_ref, dispatch_at_unix_ns, provider_observation_kind, provider_observation_ref, provider_observation_at_unix_ns, reconciliation_kind, reconciliation_ref, reconciliation_at_unix_ns, expires_at_unix_ns, retention_state, unavailable_at_unix_ns, unavailable_reason, last_mutation_ref, latest_operation_kind, latest_operation_input_digest, codec_version, replay_scope, intent_format, intent_commitment, context_commitment, envelope_wrapper_format, envelope_payload_format, envelope_algorithm, envelope_ref, envelope_size, envelope_sha256, binding_key_id, binding_key_fingerprint, envelope_key_id, envelope_key_fingerprint)
SELECT claim_rowid, caller_ref, submit_key_ref, plan_binding, witness_resolved_mask, witness_inapplicable_mask, phase_tag, run_ref, receipt_ref, revision, created_at_unix_ns, updated_at_unix_ns, assigned_at_unix_ns, effect_intent_ref, effect_intent_at_unix_ns, staging_ref, staging_at_unix_ns, dispatch_ref, dispatch_at_unix_ns, provider_observation_kind, provider_observation_ref, provider_observation_at_unix_ns, reconciliation_kind, reconciliation_ref, reconciliation_at_unix_ns, expires_at_unix_ns, retention_state, unavailable_at_unix_ns, unavailable_reason, last_mutation_ref, latest_operation_kind, latest_operation_input_digest, codec_version, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL FROM reliable_submit_claims_v2;
CREATE TABLE reliable_submit_migration3_assert (
  ok INTEGER NOT NULL CHECK (ok=1)
) STRICT;
INSERT INTO reliable_submit_migration3_assert(ok)
SELECT CASE WHEN
  (SELECT count(*) FROM reliable_submit_claims_v2) =
  (SELECT count(*) FROM reliable_submit_claims)
  AND NOT EXISTS (
    SELECT claim_rowid, caller_ref, submit_key_ref, plan_binding, witness_resolved_mask, witness_inapplicable_mask, phase_tag, run_ref, receipt_ref, revision, created_at_unix_ns, updated_at_unix_ns, assigned_at_unix_ns, effect_intent_ref, effect_intent_at_unix_ns, staging_ref, staging_at_unix_ns, dispatch_ref, dispatch_at_unix_ns, provider_observation_kind, provider_observation_ref, provider_observation_at_unix_ns, reconciliation_kind, reconciliation_ref, reconciliation_at_unix_ns, expires_at_unix_ns, retention_state, unavailable_at_unix_ns, unavailable_reason, last_mutation_ref, latest_operation_kind, latest_operation_input_digest, codec_version FROM reliable_submit_claims_v2
    EXCEPT SELECT claim_rowid, caller_ref, submit_key_ref, plan_binding, witness_resolved_mask, witness_inapplicable_mask, phase_tag, run_ref, receipt_ref, revision, created_at_unix_ns, updated_at_unix_ns, assigned_at_unix_ns, effect_intent_ref, effect_intent_at_unix_ns, staging_ref, staging_at_unix_ns, dispatch_ref, dispatch_at_unix_ns, provider_observation_kind, provider_observation_ref, provider_observation_at_unix_ns, reconciliation_kind, reconciliation_ref, reconciliation_at_unix_ns, expires_at_unix_ns, retention_state, unavailable_at_unix_ns, unavailable_reason, last_mutation_ref, latest_operation_kind, latest_operation_input_digest, codec_version FROM reliable_submit_claims)
  AND NOT EXISTS (
    SELECT claim_rowid, caller_ref, submit_key_ref, plan_binding, witness_resolved_mask, witness_inapplicable_mask, phase_tag, run_ref, receipt_ref, revision, created_at_unix_ns, updated_at_unix_ns, assigned_at_unix_ns, effect_intent_ref, effect_intent_at_unix_ns, staging_ref, staging_at_unix_ns, dispatch_ref, dispatch_at_unix_ns, provider_observation_kind, provider_observation_ref, provider_observation_at_unix_ns, reconciliation_kind, reconciliation_ref, reconciliation_at_unix_ns, expires_at_unix_ns, retention_state, unavailable_at_unix_ns, unavailable_reason, last_mutation_ref, latest_operation_kind, latest_operation_input_digest, codec_version FROM reliable_submit_claims
    EXCEPT SELECT claim_rowid, caller_ref, submit_key_ref, plan_binding, witness_resolved_mask, witness_inapplicable_mask, phase_tag, run_ref, receipt_ref, revision, created_at_unix_ns, updated_at_unix_ns, assigned_at_unix_ns, effect_intent_ref, effect_intent_at_unix_ns, staging_ref, staging_at_unix_ns, dispatch_ref, dispatch_at_unix_ns, provider_observation_kind, provider_observation_ref, provider_observation_at_unix_ns, reconciliation_kind, reconciliation_ref, reconciliation_at_unix_ns, expires_at_unix_ns, retention_state, unavailable_at_unix_ns, unavailable_reason, last_mutation_ref, latest_operation_kind, latest_operation_input_digest, codec_version FROM reliable_submit_claims_v2)
THEN 1 ELSE 0 END;
DROP TABLE reliable_submit_migration3_assert;
DROP TABLE reliable_submit_claims_v2;
CREATE UNIQUE INDEX reliable_submit_claims_envelope_ref_unique
ON reliable_submit_claims(envelope_ref);
CREATE TRIGGER reliable_submit_claims_no_delete
BEFORE DELETE ON reliable_submit_claims
BEGIN SELECT RAISE(ABORT, 'reliable submit claim deletion is forbidden'); END;
CREATE TRIGGER reliable_submit_claims_guard_insert_v3
BEFORE INSERT ON reliable_submit_claims
BEGIN
  SELECT CASE WHEN NEW.codec_version IS NOT 3 THEN RAISE(ABORT, 'new claim requires codec 3') END;
  SELECT CASE WHEN NEW.revision IS NOT 1 OR NEW.phase_tag IS NOT 1
    OR NEW.latest_operation_kind IS NOT 1 THEN RAISE(ABORT, 'invalid synthetic initial shape') END;
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
  SELECT CASE WHEN NEW.replay_scope IS NOT NULL OR NEW.intent_format IS NOT NULL OR NEW.intent_commitment IS NOT NULL OR NEW.context_commitment IS NOT NULL OR NEW.envelope_wrapper_format IS NOT NULL OR NEW.envelope_payload_format IS NOT NULL OR NEW.envelope_algorithm IS NOT NULL OR NEW.envelope_ref IS NOT NULL OR NEW.envelope_size IS NOT NULL OR NEW.envelope_sha256 IS NOT NULL OR NEW.binding_key_id IS NOT NULL OR NEW.binding_key_fingerprint IS NOT NULL OR NEW.envelope_key_id IS NOT NULL OR NEW.envelope_key_fingerprint IS NOT NULL THEN RAISE(ABORT, 'legacy custody fields must remain NULL') END;
  SELECT CASE WHEN OLD.codec_version = 3 THEN RAISE(ABORT, 'immutable synthetic claim') END;
  SELECT CASE WHEN NEW.caller_ref IS NOT OLD.caller_ref THEN RAISE(ABORT, 'immutable caller reference') END;
  SELECT CASE WHEN NEW.submit_key_ref IS NOT OLD.submit_key_ref THEN RAISE(ABORT, 'immutable submit key reference') END;
  SELECT CASE WHEN NEW.plan_binding IS NOT OLD.plan_binding THEN RAISE(ABORT, 'immutable plan binding') END;
  SELECT CASE WHEN NEW.witness_resolved_mask IS NOT OLD.witness_resolved_mask THEN RAISE(ABORT, 'immutable witness') END;
  SELECT CASE WHEN NEW.witness_inapplicable_mask IS NOT OLD.witness_inapplicable_mask THEN RAISE(ABORT, 'immutable witness') END;
  SELECT CASE WHEN NEW.created_at_unix_ns IS NOT OLD.created_at_unix_ns THEN RAISE(ABORT, 'immutable creation time') END;
  SELECT CASE WHEN NOT ((OLD.codec_version = 1 AND NEW.codec_version = 2) OR (OLD.codec_version = 2 AND NEW.codec_version = 2)) THEN RAISE(ABORT, 'codec version can only advance to v2') END;
  SELECT CASE WHEN NEW.revision != OLD.revision + 1 THEN RAISE(ABORT, 'revision must increment by one') END;
  SELECT CASE WHEN NEW.last_mutation_ref = OLD.last_mutation_ref THEN RAISE(ABORT, 'mutation reference must change with revision') END;
  SELECT CASE WHEN NEW.latest_operation_kind IS NULL THEN RAISE(ABORT, 'latest operation kind is required') END;
  SELECT CASE WHEN NEW.latest_operation_input_digest IS NULL THEN RAISE(ABORT, 'latest operation input digest is required') END;
  SELECT CASE WHEN OLD.run_ref IS NOT NULL AND (NEW.run_ref IS NULL OR NEW.run_ref IS NOT OLD.run_ref) THEN RAISE(ABORT, 'immutable run reference') END;
  SELECT CASE WHEN OLD.receipt_ref IS NOT NULL AND (NEW.receipt_ref IS NULL OR NEW.receipt_ref IS NOT OLD.receipt_ref) THEN RAISE(ABORT, 'immutable receipt reference') END;
  SELECT CASE WHEN OLD.phase_tag IN (6, 7) AND NEW.phase_tag != OLD.phase_tag THEN RAISE(ABORT, 'terminal phase is immutable') END;
  SELECT CASE WHEN OLD.retention_state != 1 AND NEW.retention_state = 1 THEN RAISE(ABORT, 'inactive claim cannot become active') END;
END;
CREATE TRIGGER reliable_submit_key_registry_no_delete
BEFORE DELETE ON reliable_submit_key_registry
BEGIN SELECT RAISE(ABORT, 'key deletion is forbidden'); END;
CREATE TRIGGER reliable_submit_key_registry_guard_insert
BEFORE INSERT ON reliable_submit_key_registry
BEGIN
  SELECT CASE WHEN EXISTS (
    SELECT 1 FROM reliable_submit_key_registry AS r
    WHERE (r.key_id COLLATE BINARY)=NEW.key_id
       OR r.material_fingerprint=NEW.material_fingerprint)
    THEN RAISE(ABORT, 'key replacement is forbidden') END;
  SELECT CASE WHEN NEW.state IS NOT 1 OR NEW.purpose NOT IN (1,2)
    OR typeof(NEW.material_fingerprint)!='blob'
    OR length(NEW.material_fingerprint)!=32
    OR NOT (CASE WHEN typeof(NEW.key_id)='text'
      AND instr(NEW.key_id,char(0)) IS 0
      AND length(CAST(NEW.key_id AS BLOB)) BETWEEN 1 AND 64
      AND substr(NEW.key_id,1,1) GLOB '[A-Za-z0-9]'
      AND substr(NEW.key_id,2) NOT GLOB '*[^A-Za-z0-9._-]*'
    THEN 1 ELSE 0 END = 1)
    THEN RAISE(ABORT, 'invalid key registration') END;
END;
CREATE TRIGGER reliable_submit_key_registry_guard_update
BEFORE UPDATE ON reliable_submit_key_registry
BEGIN
  SELECT CASE WHEN NEW.key_id IS NOT OLD.key_id
    OR NEW.purpose IS NOT OLD.purpose
    OR NEW.material_fingerprint IS NOT OLD.material_fingerprint
    OR NEW.state IS NULL
    OR NOT ((OLD.state=1 AND NEW.state IN (2,3))
         OR (OLD.state=2 AND NEW.state=3))
    THEN RAISE(ABORT, 'invalid key transition') END;
END;
CREATE TRIGGER reliable_submit_seal_use_no_delete
BEFORE DELETE ON reliable_submit_seal_use
BEGIN SELECT RAISE(ABORT, 'seal-use deletion is forbidden'); END;
CREATE TRIGGER reliable_submit_seal_use_guard_insert
BEFORE INSERT ON reliable_submit_seal_use
BEGIN
  SELECT CASE WHEN EXISTS (
    SELECT 1 FROM reliable_submit_seal_use AS c
    WHERE (c.envelope_key_id COLLATE BINARY)=NEW.envelope_key_id)
    OR NEW.granted_count IS NOT 0
    OR NOT (CASE WHEN typeof(NEW.envelope_key_id)='text'
      AND instr(NEW.envelope_key_id,char(0)) IS 0
      AND length(CAST(NEW.envelope_key_id AS BLOB)) BETWEEN 1 AND 64
      AND substr(NEW.envelope_key_id,1,1) GLOB '[A-Za-z0-9]'
      AND substr(NEW.envelope_key_id,2) NOT GLOB '*[^A-Za-z0-9._-]*'
    THEN 1 ELSE 0 END = 1)
    OR NOT EXISTS (
      SELECT 1 FROM reliable_submit_key_registry AS r
      WHERE (r.key_id COLLATE BINARY)=NEW.envelope_key_id
        AND r.purpose=2 AND r.state=1)
    THEN RAISE(ABORT, 'invalid seal-use initialization') END;
END;
CREATE TRIGGER reliable_submit_seal_use_guard_update
BEFORE UPDATE ON reliable_submit_seal_use
BEGIN
  SELECT CASE WHEN NEW.envelope_key_id IS NOT OLD.envelope_key_id
    OR NEW.granted_count IS NOT OLD.granted_count+1
    OR NEW.granted_count>4294967296
    OR NOT EXISTS (
      SELECT 1 FROM reliable_submit_key_registry AS r
      WHERE (r.key_id COLLATE BINARY)=OLD.envelope_key_id
        AND r.purpose=2 AND r.state=1)
    THEN RAISE(ABORT, 'invalid seal-use increment') END;
END;
`
