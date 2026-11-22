package admission

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"sort"
	"strings"

	"context"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"

	"execution-substrate/es/admission/internal/reliablesubmit"
	evidencev1 "execution-substrate/internal/contracts/evidence/v1"
)

// The test-only TLV reader/writer is limited to the all-present scope-3 outer
// object and provenance object. It does not call the production replay codec.
func operationalVectorFields(t *testing.T, raw []byte, count int) [][]byte {
	t.Helper()
	if len(raw) < 2 || int(binary.BigEndian.Uint16(raw[:2])) != count {
		t.Fatalf("independent TLV count: bytes=%d want=%d", len(raw), count)
	}
	fields := make([][]byte, 0, count)
	offset := 2
	for i := 0; i < count; i++ {
		if len(raw)-offset < 7 || int(binary.BigEndian.Uint16(raw[offset:])) != i+1 || raw[offset+2] != 1 {
			t.Fatalf("independent TLV field %d header", i+1)
		}
		length := int(binary.BigEndian.Uint32(raw[offset+3:]))
		offset += 7
		if length < 0 || len(raw)-offset < length {
			t.Fatalf("independent TLV field %d length", i+1)
		}
		fields = append(fields, bytes.Clone(raw[offset:offset+length]))
		offset += length
	}
	if offset != len(raw) {
		t.Fatal("independent TLV trailing bytes")
	}
	return fields
}

func operationalVectorObject(fields ...[]byte) []byte {
	result := binary.BigEndian.AppendUint16(nil, uint16(len(fields)))
	for i, field := range fields {
		result = binary.BigEndian.AppendUint16(result, uint16(i+1))
		result = append(result, 1)
		result = binary.BigEndian.AppendUint32(result, uint32(len(field)))
		result = append(result, field...)
	}
	return result
}

func operationalVectorReplaceProvenance(t *testing.T, wire []byte, kind string, record []byte) []byte {
	t.Helper()
	if len(wire) < 14 || string(wire[:8]) != "ESRSPAY3" || binary.BigEndian.Uint16(wire[8:10]) != 3 ||
		int(binary.BigEndian.Uint32(wire[10:14])) != len(wire)-14 {
		t.Fatal("independent scope-3 header mismatch")
	}
	fields := operationalVectorFields(t, wire[14:], 11)
	provenance := operationalVectorFields(t, fields[7], 6)
	provenance[0], provenance[4] = []byte(kind), bytes.Clone(record)
	fields[7] = operationalVectorObject(provenance...)
	body := operationalVectorObject(fields...)
	result := binary.BigEndian.AppendUint16([]byte("ESRSPAY3"), 3)
	result = binary.BigEndian.AppendUint32(result, uint32(len(body)))
	return append(result, body...)
}

type operationalVectorField struct {
	present bool
	value   []byte
}

func operationalVectorOptional(present bool, value []byte) operationalVectorField {
	if !present {
		value = nil
	}
	return operationalVectorField{present: present, value: value}
}

func operationalVectorTLV(fields ...operationalVectorField) []byte {
	result := binary.BigEndian.AppendUint16(nil, uint16(len(fields)))
	for i, field := range fields {
		result = binary.BigEndian.AppendUint16(result, uint16(i+1))
		if field.present {
			result = append(result, 1)
		} else {
			result = append(result, 0)
		}
		result = binary.BigEndian.AppendUint32(result, uint32(len(field.value)))
		result = append(result, field.value...)
	}
	return result
}

func operationalVectorPresent(value []byte) operationalVectorField {
	return operationalVectorField{present: true, value: value}
}

func operationalVectorSequence(values ...[]byte) []byte {
	result := binary.BigEndian.AppendUint16(nil, uint16(len(values)))
	for _, value := range values {
		result = binary.BigEndian.AppendUint32(result, uint32(len(value)))
		result = append(result, value...)
	}
	return result
}

func operationalVectorStringMap(value map[string]string) []byte {
	keys := make([]string, 0, len(value))
	for key := range value {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := binary.BigEndian.AppendUint16(nil, uint16(len(keys)))
	for _, key := range keys {
		result = binary.BigEndian.AppendUint16(result, uint16(len(key)))
		result = append(result, key...)
		result = binary.BigEndian.AppendUint32(result, uint32(len(value[key])))
		result = append(result, value[key]...)
	}
	return result
}

func operationalVectorU32(value uint32) []byte { return binary.BigEndian.AppendUint32(nil, value) }
func operationalVectorU64(value uint64) []byte { return binary.BigEndian.AppendUint64(nil, value) }
func operationalVectorBool(value bool) []byte {
	if value {
		return []byte{1}
	}
	return []byte{0}
}

// PB1 vector leaves use the published field/tag/length grammar. This builder
// never invokes the production binding encoder or reads its output.
func operationalVectorPBField(id uint16, tag byte, payload []byte) []byte {
	result := binary.BigEndian.AppendUint16(nil, id)
	result = append(result, tag)
	result = binary.BigEndian.AppendUint64(result, uint64(len(payload)))
	return append(result, payload...)
}

func operationalVectorPBRecord(id uint16, fields ...[]byte) []byte {
	return operationalVectorPBField(id, 4, bytes.Join(fields, nil))
}

func operationalVectorPBString(id uint16, value string) []byte {
	return operationalVectorPBField(id, 1, []byte(value))
}
func operationalVectorPBI64(id uint16, value int64) []byte {
	return operationalVectorPBField(id, 2, operationalVectorU64(uint64(value)))
}
func operationalVectorPBBool(id uint16, value bool) []byte {
	return operationalVectorPBField(id, 3, operationalVectorBool(value))
}
func operationalVectorPBState(id uint16, value byte) []byte {
	return operationalVectorPBField(id, 8, []byte{value})
}

func operationalVectorPBDescriptor(id uint16, content []byte, state byte) []byte {
	fields := [][]byte{operationalVectorPBState(1, state)}
	if state == 1 {
		sum := sha256.Sum256(content)
		fields = append(fields, operationalVectorPBI64(2, int64(len(content))), operationalVectorPBField(3, 7, sum[:]))
	}
	return operationalVectorPBRecord(id, fields...)
}

func operationalVectorPBStrings(id uint16, values []string) []byte {
	payload := operationalVectorU64(uint64(len(values)))
	for _, value := range values {
		payload = binary.BigEndian.AppendUint64(payload, uint64(len(value)))
		payload = append(payload, value...)
	}
	return operationalVectorPBField(id, 5, payload)
}

func operationalVectorPBMap(id uint16, values map[string]string) []byte {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	payload := operationalVectorU64(uint64(len(keys)))
	for _, key := range keys {
		payload = binary.BigEndian.AppendUint64(payload, uint64(len(key)))
		payload = append(payload, key...)
		payload = binary.BigEndian.AppendUint64(payload, uint64(len(values[key])))
		payload = append(payload, values[key]...)
	}
	return operationalVectorPBField(id, 6, payload)
}

func operationalVectorBinding(t *testing.T, original verifiedOperationalOriginal, keys operationalOriginalKeys) []byte {
	t.Helper()
	p := original.resolved.plan
	m := original.resolved.material
	if len(p.mounts) != 0 || len(m.mounts) != 0 {
		t.Fatal("independent scope-3 vector fixture unexpectedly acquired mounts")
	}
	family := operationalVectorPBRecord(1,
		operationalVectorPBString(1, "execution-substrate.reliable-submit-request/v1"),
		operationalVectorPBString(2, "execution-substrate.reliable-submit/v1"),
		operationalVectorPBString(3, p.requestSchemaVersion),
		operationalVectorPBString(4, p.invocationSchemaVersion))
	profile := operationalVectorPBRecord(6, operationalVectorPBString(1, p.runtimeProfile.name), operationalVectorPBString(2, p.runtimeProfile.image))
	primary := operationalVectorPBRecord(7, operationalVectorPBString(1, p.artifactDigest),
		operationalVectorPBString(2, p.payloadDigest), operationalVectorPBDescriptor(3, m.payloadBytes, 1))
	command := operationalVectorPBRecord(10, operationalVectorPBString(1, p.runtimeCommand.executable),
		operationalVectorPBStrings(2, p.runtimeCommand.arguments))
	var emptyMounts []byte = operationalVectorU64(0)
	location := p.authority.codexCredential
	var codex []byte
	if !location.applicable {
		codex = operationalVectorPBRecord(3, operationalVectorPBState(1, 2))
	} else {
		codex = operationalVectorPBRecord(3, operationalVectorPBState(1, 1),
			operationalVectorPBString(2, location.cliPath), operationalVectorPBString(3, location.credentialSource),
			operationalVectorPBString(4, location.vaultSecretPath), operationalVectorPBString(5, location.vaultSecretField))
	}
	vault := p.authority.workloadVault
	authority := operationalVectorPBRecord(14, operationalVectorPBState(1, 1),
		operationalVectorPBString(2, p.authority.runtimeProfileName), codex,
		operationalVectorPBRecord(4, operationalVectorPBString(1, vault.mode), operationalVectorPBString(2, vault.address),
			operationalVectorPBString(3, vault.authMount), operationalVectorPBString(4, vault.authRole),
			operationalVectorPBString(5, vault.jwtAudience)),
		operationalVectorPBString(5, p.authority.workloadZoneVaultConfigDigest),
		operationalVectorPBRecord(6, operationalVectorPBBool(1, p.authority.trustMaterial.vaultCACert),
			operationalVectorPBBool(2, p.authority.trustMaterial.workloadTLSBundle)))
	support := operationalVectorPBRecord(15, operationalVectorPBString(1, p.runtimeSupportDigest),
		operationalVectorPBDescriptor(2, m.runtimeSupportBytes, 1))
	job := p.jobEnvelope
	jobRecord := operationalVectorPBRecord(17,
		operationalVectorPBString(1, job.jobType), operationalVectorPBString(2, job.groupName),
		operationalVectorPBI64(3, int64(job.groupCount)), operationalVectorPBString(4, job.taskName),
		operationalVectorPBString(5, job.driver), operationalVectorPBString(6, job.user),
		operationalVectorPBBool(7, job.privileged), operationalVectorPBStrings(8, job.securityOptions),
		operationalVectorPBRecord(9,
			operationalVectorPBI64(1, int64(job.restartPolicy.attempts)), operationalVectorPBString(2, job.restartPolicy.mode),
			operationalVectorPBI64(3, job.restartPolicy.interval), operationalVectorPBI64(4, job.restartPolicy.delay)),
		operationalVectorPBRecord(10,
			operationalVectorPBI64(1, int64(job.reschedulePolicy.attempts)), operationalVectorPBBool(2, job.reschedulePolicy.unlimited),
			operationalVectorPBI64(3, job.reschedulePolicy.delay), operationalVectorPBString(4, job.reschedulePolicy.delayFunction),
			operationalVectorPBI64(5, job.reschedulePolicy.maxDelay)))
	vaultState := byte(0)
	if len(m.trust.vaultCACertBytes) != 0 {
		vaultState = 1
	}
	tlsState := byte(0)
	if len(m.trust.workloadTLSBundleBytes) != 0 {
		tlsState = 1
	}
	trust := operationalVectorPBRecord(18, operationalVectorPBDescriptor(1, m.trust.vaultCACertBytes, vaultState),
		operationalVectorPBDescriptor(2, m.trust.workloadTLSBundleBytes, tlsState))
	canonical := bytes.Join([][]byte{
		family, operationalVectorPBString(2, string(p.mode)), operationalVectorPBI64(3, int64(p.timeoutSeconds)),
		operationalVectorPBI64(4, int64(p.resources.cpu)), operationalVectorPBI64(5, int64(p.resources.memoryMB)),
		profile, primary, operationalVectorPBString(8, p.derivationSpecDigest), operationalVectorPBString(9, p.outputID),
		command, operationalVectorPBMap(11, p.semanticEnvironment), operationalVectorPBField(12, 5, emptyMounts),
		operationalVectorPBBool(13, p.networkAccess), authority, support,
		operationalVectorPBI64(16, p.runtimeIdentityTmpfsSize), jobRecord, trust,
	}, nil)
	header := append([]byte("ESRS-PB\x00\x01"), byte(len(keys.bindingID)>>8), byte(len(keys.bindingID)))
	header = append(header, keys.bindingID...)
	mac := hmac.New(sha256.New, keys.key.bytes[:])
	_, _ = mac.Write([]byte("execution-substrate/reliable-effective-plan/v1\x00"))
	_, _ = mac.Write(header)
	_, _ = mac.Write(canonical)
	return append(header, mac.Sum(nil)...)
}

func operationalVectorDescriptor(content []byte, present bool) []byte {
	result := make([]byte, 41)
	if present {
		result[0] = 1
		binary.BigEndian.PutUint64(result[1:9], uint64(len(content)))
		sum := sha256.Sum256(content)
		copy(result[9:], sum[:])
	}
	return result
}

func operationalVectorWire(t *testing.T, f *operationalFixture, original verifiedOperationalOriginal, evidence string) []byte {
	t.Helper()
	i, p, m, r := original.delivery.originalIntent, original.resolved.plan, original.resolved.material, f.domain.realm
	if len(i.mounts.value) != 0 || len(p.mounts) != 0 || len(m.mounts) != 0 {
		t.Fatal("independent complete vector requires the inert no-mount fixture")
	}
	caller := sha256.Sum256([]byte("es/reliable-submit/caller-ref/v1\x00" + f.domain.caller.String()))
	keyRaw := bytes.Repeat([]byte{0x31}, 32)
	keyPreimage := append([]byte("es/reliable-submit/submit-key-ref/v1\x00"), caller[:]...)
	keyPreimage = append(keyPreimage, keyRaw...)
	key := sha256.Sum256(keyPreimage)
	identity := operationalVectorObject(caller[:], key[:])
	argv := make([][]byte, 0, len(i.argv.value))
	for _, arg := range i.argv.value {
		argv = append(argv, []byte(arg))
	}
	var resources []byte
	if i.resources.present {
		resources = operationalVectorObject(operationalVectorU32(uint32(i.resources.value.CPU)),
			operationalVectorU32(uint32(i.resources.value.MemoryMB)))
	}
	intent := operationalVectorTLV(
		operationalVectorPresent([]byte(i.outerSchema)), operationalVectorPresent([]byte(i.contract)),
		operationalVectorPresent([]byte{1}), operationalVectorOptional(i.invocationSchema.present, []byte(i.invocationSchema.value)),
		operationalVectorPresent([]byte(i.artifactDigest)), operationalVectorPresent([]byte(i.derivationDigest)),
		operationalVectorPresent([]byte(i.outputID)), operationalVectorOptional(i.mode.present, []byte(i.mode.value)),
		operationalVectorOptional(i.timeout.present, operationalVectorU32(i.timeout.value)),
		operationalVectorOptional(i.resources.present, resources),
		operationalVectorOptional(i.argv.present, operationalVectorSequence(argv...)),
		operationalVectorOptional(i.env.present, operationalVectorStringMap(i.env.value)),
		operationalVectorOptional(i.mounts.present, operationalVectorSequence()),
		operationalVectorOptional(i.annotations.present, operationalVectorStringMap(i.annotations.value)),
		operationalVectorOptional(i.profile.present, []byte(i.profile.value)))
	arguments := make([][]byte, 0, len(p.runtimeCommand.arguments))
	for _, arg := range p.runtimeCommand.arguments {
		arguments = append(arguments, []byte(arg))
	}
	security := make([][]byte, 0, len(p.jobEnvelope.securityOptions))
	for _, option := range p.jobEnvelope.securityOptions {
		security = append(security, []byte(option))
	}
	a := p.authority
	authority := operationalVectorObject(
		[]byte(a.runtimeProfileName), operationalVectorBool(a.codexCredential.applicable),
		[]byte(a.codexCredential.cliPath), []byte(a.codexCredential.credentialSource),
		[]byte(a.codexCredential.vaultSecretPath), []byte(a.codexCredential.vaultSecretField),
		[]byte(a.workloadVault.mode), []byte(a.workloadVault.address), []byte(a.workloadVault.authMount),
		[]byte(a.workloadVault.authRole), []byte(a.workloadVault.jwtAudience),
		[]byte(a.workloadZoneVaultConfigDigest), operationalVectorBool(a.trustMaterial.vaultCACert),
		operationalVectorBool(a.trustMaterial.workloadTLSBundle))
	job := p.jobEnvelope
	jobObject := operationalVectorObject(
		[]byte(job.jobType), []byte(job.groupName), operationalVectorU32(uint32(job.groupCount)),
		[]byte(job.taskName), []byte(job.driver), []byte(job.user), operationalVectorBool(job.privileged),
		operationalVectorSequence(security...), operationalVectorU32(uint32(job.restartPolicy.attempts)),
		[]byte(job.restartPolicy.mode), operationalVectorU64(uint64(job.restartPolicy.interval)),
		operationalVectorU64(uint64(job.restartPolicy.delay)), operationalVectorU32(uint32(job.reschedulePolicy.attempts)),
		operationalVectorBool(job.reschedulePolicy.unlimited), operationalVectorU64(uint64(job.reschedulePolicy.delay)),
		[]byte(job.reschedulePolicy.delayFunction), operationalVectorU64(uint64(job.reschedulePolicy.maxDelay)))
	plan := operationalVectorObject(
		operationalVectorObject([]byte(p.requestSchemaVersion), []byte(p.invocationSchemaVersion)),
		operationalVectorObject([]byte(p.mode), operationalVectorU32(uint32(p.timeoutSeconds))),
		operationalVectorObject(operationalVectorU32(uint32(p.resources.cpu)), operationalVectorU32(uint32(p.resources.memoryMB))),
		operationalVectorObject([]byte(p.runtimeProfile.name), []byte(p.runtimeProfile.image)),
		operationalVectorObject([]byte(p.artifactDigest), []byte(p.payloadDigest)),
		operationalVectorObject([]byte(p.derivationSpecDigest), []byte(p.outputID)),
		operationalVectorObject([]byte(p.runtimeCommand.executable), operationalVectorSequence(arguments...)),
		operationalVectorStringMap(p.semanticEnvironment), operationalVectorSequence(), operationalVectorBool(p.networkAccess),
		authority, []byte(p.runtimeSupportDigest), operationalVectorU64(uint64(p.runtimeIdentityTmpfsSize)), jobObject)
	material := operationalVectorTLV(
		operationalVectorPresent(bytes.Clone(m.payloadBytes)), operationalVectorPresent(bytes.Clone(m.runtimeSupportBytes)),
		operationalVectorPresent(operationalVectorSequence()),
		operationalVectorOptional(len(m.trust.vaultCACertBytes) != 0, bytes.Clone(m.trust.vaultCACertBytes)),
		operationalVectorOptional(len(m.trust.workloadTLSBundleBytes) != 0, bytes.Clone(m.trust.workloadTLSBundleBytes)))
	binding := operationalVectorBinding(t, original, f.domain.keys)
	bindingValue := binary.BigEndian.AppendUint16(nil, uint16(len(binding)))
	bindingValue = append(bindingValue, binding...)
	materialIdentities := operationalVectorObject(
		operationalVectorDescriptor(m.payloadBytes, true), operationalVectorDescriptor(m.runtimeSupportBytes, true),
		operationalVectorSequence(), operationalVectorDescriptor(m.trust.vaultCACertBytes, len(m.trust.vaultCACertBytes) != 0),
		operationalVectorDescriptor(m.trust.workloadTLSBundleBytes, len(m.trust.workloadTLSBundleBytes) != 0))
	assessment := operationalVectorObject(bindingValue, []byte{0x3f, 0xff}, []byte{0, 0}, materialIdentities)
	image := operationalVectorObject([]byte(p.runtimeProfile.image), r.image[:], []byte(r.imageIssuer), []byte{2}, []byte(r.datacenter))
	placement := operationalVectorObject([]byte(r.staging), []byte(r.results), []byte(r.spireSocket),
		[]byte(r.datacenter), operationalVectorU32(uint32(r.owner.UID)), operationalVectorU32(uint32(r.owner.GID)))
	kind := "operational_local_v2"
	provenanceLeaf := []byte(evidence)
	if evidence == "" {
		kind = "operational_local_v1"
		provenanceLeaf = operationalVectorSequence()
	}
	provenance := operationalVectorObject([]byte(kind), []byte(p.artifactDigest), []byte(p.payloadDigest),
		[]byte(p.runtimeSupportDigest), provenanceLeaf,
		operationalVectorObject(operationalVectorBool(a.trustMaterial.vaultCACert), operationalVectorBool(a.trustMaterial.workloadTLSBundle)))
	keys := operationalVectorObject([]byte{0, 1}, []byte(f.domain.keys.bindingID), []byte(f.domain.keys.envelopeID),
		[]byte{0, 3}, []byte{0, 3}, []byte{0, 1})
	realm := operationalVectorObject([]byte{0, 1}, r.installation[:], operationalVectorU64(r.epoch), r.provider[:], r.spki[:],
		[]byte(r.host), binary.BigEndian.AppendUint16(nil, r.port), []byte(r.region), []byte(r.datacenter),
		[]byte("es-operational-v1"), []byte(r.staging), []byte(r.results), []byte(r.spireSocket), r.build[:], r.template[:])
	body := operationalVectorObject(identity, intent, plan, material, assessment, image, placement, provenance, keys, []byte{3}, realm)
	wire := binary.BigEndian.AppendUint16([]byte("ESRSPAY3"), 3)
	wire = binary.BigEndian.AppendUint32(wire, uint32(len(body)))
	return append(wire, body...)
}

func TestOperationalOriginalBindingAndCustody(t *testing.T) {
	ctx := context.Background()
	f := makeOperationalFixture(t, "")
	caller, err := newSyntheticCallerFact(f.domain.caller.String())
	if err != nil {
		t.Fatal(err)
	}
	request, err := parsePrivateReplayDelivery(f.raw, caller)
	if err != nil {
		t.Fatal(err)
	}
	resolved, failure := f.service.resolveExecutionForSubmit(ctx, request.request)
	if failure != nil {
		t.Fatalf("resolve selected fixture: %s", failure.Code)
	}
	if !validateOperationalPlan(request, resolved, f.domain.realm) {
		t.Fatalf("selected fixture: mode=%q profile=%q network=%t image=%t args=%d stage=%t result=%t identity=%t owner=%t",
			resolved.plan.mode, resolved.plan.runtimeProfile.name, resolved.plan.networkAccess, resolved.plan.runtimeProfile.image == f.service.cfg.Execution.BaseImage,
			len(resolved.plan.runtimeCommand.arguments), resolved.custodyPlacement.stagingRootDir == f.domain.realm.staging,
			resolved.custodyPlacement.resultsRootDir == f.domain.realm.results, resolved.host.spireSourceDir == filepath.Dir(f.domain.realm.spireSocket),
			resolved.host.owner == f.domain.realm.owner)
	}
	original, err := f.service.composeOperationalOriginal(ctx, request, f.domain.keys, f.domain.realm)
	if err != nil {
		t.Fatalf("compose scope 3 original: %v", err)
	}
	if _, err := verifyOperationalOriginal(original.wire, f.domain.keys, f.domain.realm); err != nil {
		t.Fatalf("verify scope 3 original: %v", err)
	}
	if _, err := reliablesubmit.MatchOperationalOriginal(request.refs.claimID, original.assessment.boundPlan, original.wire); err != nil {
		t.Fatalf("store shape rejected scope 3 original: %v", err)
	}
	if got := f.domain.custody.EstablishOperational(ctx, request.refs.claimID, original.assessment.boundPlan, f.domain.keys.storage, original.wire).Disposition(); got != reliablesubmit.OperationalApplied {
		var cutoff int
		if err := f.db.QueryRow("SELECT count(*) FROM reliable_submit_seal_use").Scan(&cutoff); err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(filepath.Join(f.root, "objects", "v1"))
		t.Fatalf("scope 3 establishment refused: %d grants=%d objects=%d err=%v", got, cutoff, len(entries), err)
	}
}

func TestOperationalHandoffIndependentBindingVectors(t *testing.T) {
	t.Run("complete signed v2 outer wire and PB1 commitment", func(t *testing.T) {
		f := makeOperationalFixture(t, "")
		original := operationalV2Original(t, f)
		var signed evidencev1.ArtifactEvidence
		if err := json.Unmarshal([]byte(f.expectedEvidence), &signed); err != nil {
			t.Fatal(err)
		}
		verifier := f.service.operationalAdmission.verifier
		claimsOnly, err := signed.Claims.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		signature, err := base64.StdEncoding.DecodeString(signed.Seal.Signature)
		if err != nil {
			t.Fatal(err)
		}
		fullRecord, err := json.Marshal(signed)
		if err != nil {
			t.Fatal(err)
		}
		claimsDigest := sha256.Sum256(claimsOnly)
		if len(f.expectedEvidence) == 0 || len(f.expectedEvidence) > 256*1024 ||
			signed.Seal.Signature == "" || signed.Seal.ContentDigest == "" ||
			!bytes.Equal(fullRecord, []byte(f.expectedEvidence)) || bytes.Equal(fullRecord, claimsOnly) ||
			signed.Seal.ContentDigest != "sha256:"+hex.EncodeToString(claimsDigest[:]) ||
			!ed25519.Verify(verifier.publicKey, claimsOnly, signature) ||
			evidencev1.Verify(signed, verifier.keyID, verifier.algorithm, verifier.publicKey) != nil {
			t.Fatal("synthetic full Claims and Seal record is not validly signed")
		}
		expected := operationalVectorWire(t, f, original, f.expectedEvidence)
		if len(expected) > 1<<20 || !bytes.Equal(expected, original.wire) {
			t.Fatalf("independent complete v2 wire differs: expected=%d actual=%d", len(expected), len(original.wire))
		}
		read, err := verifyOperationalOriginal(expected, f.domain.keys, f.domain.realm)
		if err != nil || read.variant != operationalOriginalV2 || read.resolved.provenanceRecord != f.expectedEvidence {
			t.Fatalf("independent full v2 reader: %v", err)
		}
		if reason := f.service.qualifyOperationalRetained(context.Background(), read, f.domain.realm); reason != reliablesubmit.OperationalReasonNone {
			t.Fatalf("independent full v2 policy qualification reason=%d", reason)
		}
		for name, mutate := range map[string]func([]byte) []byte{
			"header scope":     func(w []byte) []byte { w[9] = 2; return w },
			"aggregate length": func(w []byte) []byte { w[13] ^= 1; return w },
			"field order":      func(w []byte) []byte { w[17] = 2; return w },
			"field presence":   func(w []byte) []byte { w[18] = 0; return w },
			"binding commitment": func(w []byte) []byte {
				fields := operationalVectorFields(t, w[14:], 11)
				assessment := operationalVectorFields(t, fields[4], 4)
				assessment[0][len(assessment[0])-1] ^= 1
				fields[4] = operationalVectorObject(assessment...)
				body := operationalVectorObject(fields...)
				return append(binary.BigEndian.AppendUint32(w[:10], uint32(len(body))), body...)
			},
			"empty evidence": func(w []byte) []byte { return operationalVectorReplaceProvenance(t, w, "operational_local_v2", nil) },
			"unknown provenance": func(w []byte) []byte {
				return operationalVectorReplaceProvenance(t, w, "operational_local_v3", []byte(f.expectedEvidence))
			},
			"evidence over cap": func(w []byte) []byte {
				return operationalVectorReplaceProvenance(t, w, "operational_local_v2", bytes.Repeat([]byte{'x'}, 256*1024+1))
			},
		} {
			t.Run(name, func(t *testing.T) {
				if _, err := verifyOperationalOriginal(mutate(bytes.Clone(expected)), f.domain.keys, f.domain.realm); err == nil {
					t.Fatal("independent v2 negative vector reached authenticated use")
				}
			})
		}
	})
	for _, checkMutants := range []bool{false, true} {
		t.Run(map[bool]string{false: "retained-fixture", true: "identity-controls"}[checkMutants], func(t *testing.T) {
			f := makeOperationalFixture(t, "")
			frame := func(b []byte, value string) []byte {
				b = binary.BigEndian.AppendUint32(b, uint32(len(value)))
				return append(b, []byte(value)...)
			}
			hmacRef := func(prefix string, value []byte) [32]byte {
				key := bytes.Repeat([]byte{181}, 32)
				mac := hmac.New(sha256.New, key)
				_, _ = mac.Write([]byte(prefix))
				_, _ = mac.Write(value)
				var ref [32]byte
				copy(ref[:], mac.Sum(nil))
				return ref
			}
			identity := func(buf []byte, name string) []byte {
				t.Helper()
				var st unix.Stat_t
				if err := unix.Lstat(name, &st); err != nil {
					t.Fatal(err)
				}
				tag := byte(2)
				if st.Mode&unix.S_IFMT == unix.S_IFDIR {
					tag = 1
				}
				buf = append(buf, tag)
				buf = binary.BigEndian.AppendUint64(buf, uint64(st.Dev))
				buf = binary.BigEndian.AppendUint64(buf, st.Ino)
				buf = binary.BigEndian.AppendUint32(buf, st.Uid)
				buf = binary.BigEndian.AppendUint32(buf, st.Gid)
				buf = binary.BigEndian.AppendUint32(buf, uint32(st.Mode)&0o7777)
				return binary.BigEndian.AppendUint64(buf, uint64(st.Nlink))
			}
			seen := false
			var evidence []byte
			f.domain.proof = &operationalHandoffProofHooks{beforeConsume: func(s *liveSender, owner *handoffOwner) {
				seen = true
				b := s.binding
				var request struct{ Job map[string]any }
				decoder := json.NewDecoder(bytes.NewReader(s.prepared))
				decoder.UseNumber()
				if err := decoder.Decode(&request); err != nil {
					t.Fatal(err)
				}
				meta := request.Job["Meta"].(map[string]any)
				correlation := meta["es_operational_correlation_v1"]
				delete(meta, "es_operational_correlation_v1")
				var canonicalJob bytes.Buffer
				encoder := json.NewEncoder(&canonicalJob)
				encoder.SetEscapeHTML(false)
				if err := encoder.Encode(request.Job); err != nil {
					t.Fatal(err)
				}
				job := bytes.TrimSuffix(canonicalJob.Bytes(), []byte("\n"))
				r := f.domain.realm
				locator := append([]byte("ESOHLOC1"), r.installation[:]...)
				locator = binary.BigEndian.AppendUint64(locator, r.epoch)
				locator = append(locator, r.provider[:]...)
				locator = append(locator, r.spki[:]...)
				locator = frame(locator, r.host)
				locator = binary.BigEndian.AppendUint16(locator, r.port)
				for _, value := range []string{r.region, r.datacenter, "es-operational-v1", request.Job["ID"].(string)} {
					locator = frame(locator, value)
				}
				locator = append(locator, r.build[:]...)
				locator = append(locator, r.template[:]...)
				wantL := sha256.Sum256(locator)
				wantP := sha256.Sum256(frame(append([]byte("ESOHJOB1"), wantL[:]...), string(job)))
				prefix := frame(bytes.Clone(b.original[:]), b.run)
				wantI := sha256.Sum256(append(append([]byte("ESOHINT1"), prefix...), wantL[:]...))
				var actualIntent, mutation []byte
				if err := f.db.QueryRow("SELECT effect_intent_ref,last_mutation_ref FROM reliable_submit_claims WHERE revision=5").Scan(&actualIntent, &mutation); err != nil {
					t.Fatal(err)
				}
				stageRoot := filepath.Join(f.domain.stage.path, b.run)
				var children []string
				if err := filepath.WalkDir(stageRoot, func(path string, entry fs.DirEntry, err error) error {
					if err != nil {
						return err
					}
					if path != stageRoot {
						children = append(children, strings.TrimPrefix(path, stageRoot+"/"))
					}
					return nil
				}); err != nil || (len(children) != 6 && len(children) != 8) {
					t.Fatalf("stage vector layout %v %v", children, err)
				}
				stage := append(append([]byte("ESOHSTG1"), prefix...), wantI[:]...)
				stage = append(stage, wantP[:]...)
				stage = identity(stage, f.domain.stage.path)
				stage = identity(stage, stageRoot)
				stage = binary.BigEndian.AppendUint16(stage, uint16(len(children)))
				for _, child := range children {
					path := filepath.Join(stageRoot, child)
					stage = identity(frame(stage, child), path)
					info, err := os.Lstat(path)
					if err != nil {
						t.Fatal(err)
					}
					var digest [32]byte
					var size uint64
					if !info.IsDir() {
						data, err := os.ReadFile(path)
						if err != nil {
							t.Fatal(err)
						}
						digest, size = sha256.Sum256(data), uint64(len(data))
					}
					stage = append(binary.BigEndian.AppendUint64(stage, size), digest[:]...)
				}
				wantS := sha256.Sum256(stage)
				marker := append(append([]byte("ESOHMRK1"), prefix...), wantI[:]...)
				for _, value := range [][32]byte{wantS, wantP, wantL} {
					marker = append(marker, value[:]...)
				}
				wantD := sha256.Sum256(binary.BigEndian.AppendUint64(append(marker, mutation...), 4))
				evidence = bytes.Clone(prefix)
				for _, value := range [][32]byte{wantS, wantD, wantP, wantL} {
					evidence = append(evidence, value[:]...)
				}
				wantC := hmacRef("ESOHCOR1", evidence)
				if wantL != b.locator || wantP != b.project || !bytes.Equal(wantI[:], actualIntent) ||
					wantS != b.stamp || wantD != b.marker || correlation != hex.EncodeToString(wantC[:]) {
					t.Fatal("independent L/P/I/S/D/C preimages disagree with captured sender")
				}
				if checkMutants {
					modeAt := 8 + len(prefix) + 64 + 25
					changed := bytes.Clone(stage)
					changed[modeAt+3] ^= 0o20
					if sha256.Sum256(changed) == b.stamp {
						t.Fatal("changed mode produced the retained stage digest")
					}
					if hmacRef("ESOHCOR1", evidence[:len(evidence)-1]) == wantC {
						t.Fatal("truncated locator produced the retained carrier")
					}
				}
			}}
			out := f.submit()
			if !seen || out.kind != operationalAccepted {
				t.Fatalf("vector fixture did not reach acceptance: %v", out.kind)
			}
			evaluation, err := hex.DecodeString(strings.ReplaceAll(operationalTestEvaluation, "-", ""))
			if err != nil {
				t.Fatal(err)
			}
			input := append(binary.BigEndian.AppendUint64(bytes.Clone(evidence), operationalTestIndex), evaluation...)
			wantW := hmacRef("ESOHEVD1", input)
			wantR := hmacRef("ESOHREC1", append(evidence, wantW[:]...))
			var gotW, gotR []byte
			if err := f.db.QueryRow("SELECT provider_observation_ref,receipt_ref FROM reliable_submit_claims WHERE revision=6").Scan(&gotW, &gotR); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(wantW[:], gotW) || !bytes.Equal(wantR[:], gotR) {
				t.Fatal("independent W/R witness preimages disagree with retained acceptance")
			}
		})
	}
}
