package admission

import (
	"crypto/hmac"
	"encoding/binary"
	"encoding/hex"
	"path/filepath"
	"slices"
	"strings"

	"execution-substrate/es/admission/internal/reliablesubmit"
)

const operationalScope = 3
const operationalNamespace = "es-operational-v1"

type operationalRealm struct {
	privateExecutionValue
	installation, provider, spki, build, template [32]byte
	epoch                                         uint64
	host, region, datacenter                      string
	port                                          uint16
	staging, results, spireSocket                 string
	imageIssuer                                   string
	image                                         [32]byte
	owner                                         executionPlatformStateOwner
}

type operationalOriginalKeys struct {
	privateExecutionValue
	storage               reliablesubmit.PrivateReplayKeys
	key                   privateBindingKey
	bindingID, envelopeID string
}

type verifiedOperationalOriginal struct {
	privateExecutionValue
	delivery   privateReplayDelivery
	resolved   resolvedExecution
	assessment admissionBindingAssessment
	wire       []byte
}

func newOperationalOriginalKeys(id string, secret []byte, envelopeID string, envelope []byte) (operationalOriginalKeys, error) {
	key, err := newPrivateBindingKey(id, secret)
	if err != nil {
		return operationalOriginalKeys{}, errPrivateReplayUnavailable
	}
	storage, err := reliablesubmit.NewPrivateReplayKeys(id, secret, envelopeID, envelope)
	if err != nil {
		return operationalOriginalKeys{}, errPrivateReplayUnavailable
	}
	return operationalOriginalKeys{storage: storage, key: key, bindingID: id, envelopeID: envelopeID}, nil
}

func (d operationalRealm) encode(e *privateReplayEncoder) []byte {
	return e.object(e.field(1, replayUint16(1)), e.field(2, d.installation[:]), e.field(3, replayUint64(d.epoch)),
		e.field(4, d.provider[:]), e.field(5, d.spki[:]), e.field(6, e.string(d.host, 253)), e.field(7, replayUint16(d.port)),
		e.field(8, e.string(d.region, 63)), e.field(9, e.string(d.datacenter, 63)), e.field(10, []byte(operationalNamespace)),
		e.field(11, e.string(d.staging, 512)), e.field(12, e.string(d.results, 512)), e.field(13, e.string(d.spireSocket, 512)),
		e.field(14, d.build[:]), e.field(15, d.template[:]))
}

func validateOperationalPlan(delivery privateReplayDelivery, resolved resolvedExecution, realm operationalRealm) bool {
	i := delivery.originalIntent
	p := resolved.plan
	h := resolved.host
	return i.invocationPresent && len(i.mounts.value) == 0 && len(resolved.material.mounts) == 0 &&
		len(p.mounts) == 0 && !p.networkAccess && p.mode == ExecutionModeAsync &&
		p.runtimeProfile.name == runtimeProfileDefaultStaticScript &&
		(!i.profile.present || i.profile.value == "" || i.profile.value == p.runtimeProfile.name) &&
		p.jobEnvelope.jobType == "batch" && p.jobEnvelope.groupCount == 1 && p.jobEnvelope.driver == "docker" &&
		i.outerSchema == reliableSubmitRequestSchemaV1 && p.requestSchemaVersion == "v1" && p.invocationSchemaVersion == "v1" &&
		p.artifactDigest == i.artifactDigest && p.derivationSpecDigest == i.derivationDigest && p.outputID == i.outputID &&
		(!i.timeout.present || int(i.timeout.value) == p.timeoutSeconds) &&
		(!i.resources.present || i.resources.value.CPU == p.resources.cpu && i.resources.value.MemoryMB == p.resources.memoryMB) &&
		len(p.runtimeCommand.arguments) >= 12 && slices.Equal(p.runtimeCommand.arguments[12:], i.argv.value) &&
		h.datacenter == realm.datacenter && h.owner == realm.owner && h.spireSourceDir == filepath.Dir(realm.spireSocket) &&
		resolved.custodyPlacement.stagingRootDir == realm.staging && resolved.custodyPlacement.resultsRootDir == realm.results &&
		realm.imageIssuer != "" && strings.HasSuffix(p.runtimeProfile.image, "@sha256:"+hex.EncodeToString(realm.image[:]))
}

func encodeOperationalOriginal(delivery privateReplayDelivery, resolved resolvedExecution, assessment admissionBindingAssessment,
	keys operationalOriginalKeys, realm operationalRealm) ([]byte, error) {
	if !validateOperationalPlan(delivery, resolved, realm) || realm.owner.UID < 0 || realm.owner.GID < 0 ||
		uint64(realm.owner.UID) > 4294967295 || uint64(realm.owner.GID) > 4294967295 {
		return nil, errPrivateReplayUnavailable
	}
	e := privateReplayEncoder{}
	identity, err := reliablesubmit.EncodePrivateReplayIdentity(delivery.refs.claimID)
	if err != nil {
		return nil, errPrivateReplayUnavailable
	}
	assessmentBytes, err := reliablesubmit.EncodePrivateReplayAssessment(assessment.boundPlan, e.materialIdentities(assessment.material))
	if err != nil {
		return nil, errPrivateReplayUnavailable
	}
	p := resolved.plan
	image := e.object(e.field(1, e.string(p.runtimeProfile.image, 1024)), e.field(2, realm.image[:]),
		e.field(3, e.string(realm.imageIssuer, 1024)), e.field(4, []byte{2}), e.field(5, e.string(realm.datacenter, 4096)))
	placement := e.object(e.field(1, e.string(realm.staging, 512)), e.field(2, e.string(realm.results, 512)),
		e.field(3, e.string(realm.spireSocket, 512)), e.field(4, e.string(realm.datacenter, 63)),
		e.field(5, replayUint32(uint32(realm.owner.UID))), e.field(6, replayUint32(uint32(realm.owner.GID))))
	trust := e.object(e.field(1, replayBool(p.authority.trustMaterial.vaultCACert)), e.field(2, replayBool(p.authority.trustMaterial.workloadTLSBundle)))
	provenance := e.object(e.field(1, []byte("operational_local_v1")), e.field(2, e.string(p.artifactDigest, 256)),
		e.field(3, e.string(p.payloadDigest, 256)), e.field(4, e.string(p.runtimeSupportDigest, 256)), e.field(5, e.sequence(nil, 8)),
		e.field(6, trust))
	body := e.object(e.field(1, identity), e.field(2, e.original(delivery.originalIntent)),
		e.field(3, e.plan(p)), e.field(4, e.material(resolved.material)), e.field(5, assessmentBytes),
		e.field(6, image), e.field(7, placement), e.field(8, provenance), e.field(9, e.keys(keys.bindingID, keys.envelopeID, operationalScope)),
		e.field(10, []byte{operationalScope}), e.field(11, realm.encode(&e)))
	if e.err != nil || len(body)+14 > 1<<20 {
		return nil, errPrivateReplayUnavailable
	}
	wire := binary.BigEndian.AppendUint16([]byte("ESRSPAY3"), operationalScope)
	wire = binary.BigEndian.AppendUint32(wire, uint32(len(body)))
	return append(wire, body...), nil
}

func verifyOperationalOriginal(wire []byte, keys operationalOriginalKeys, realm operationalRealm) (verifiedOperationalOriginal, error) {
	if len(wire) < 16 || len(wire) > 1<<20 || string(wire[:8]) != "ESRSPAY3" ||
		binary.BigEndian.Uint16(wire[8:10]) != operationalScope || int(binary.BigEndian.Uint32(wire[10:14])) != len(wire)-14 {
		return verifiedOperationalOriginal{}, errPrivateReplayUnavailable
	}
	r := privateReplayReader{}
	f, err := r.object(wire[14:], 11, 1, 1)
	if err != nil {
		return verifiedOperationalOriginal{}, err
	}
	for _, field := range f {
		if !field.present {
			return verifiedOperationalOriginal{}, errPrivateReplayUnavailable
		}
	}
	refs, err := r.identity(f[0].value)
	if err != nil {
		return verifiedOperationalOriginal{}, err
	}
	intent, err := r.original(f[1].value)
	if err != nil {
		return verifiedOperationalOriginal{}, err
	}
	plan, err := r.plan(f[2].value)
	if err != nil {
		return verifiedOperationalOriginal{}, err
	}
	material, err := r.material(f[3].value)
	if err != nil {
		return verifiedOperationalOriginal{}, err
	}
	captured, err := newResolvedExecutionMaterial(&material)
	if err != nil {
		return verifiedOperationalOriginal{}, errPrivateReplayUnavailable
	}
	family, err := newReliableBindingFamily(intent.outerSchema, intent.contract)
	if err != nil {
		return verifiedOperationalOriginal{}, errPrivateReplayUnavailable
	}
	resolved := resolvedExecution{plan: newResolvedExecutionPlan(plan), material: captured,
		host:             newHostMaterializationContext(realm.staging, realm.results, realm.owner, filepath.Dir(realm.spireSocket), realm.datacenter),
		custodyPlacement: resolvedCustodyPlacement{stagingRootDir: realm.staging, resultsRootDir: realm.results}}
	delivery := privateReplayDelivery{originalIntent: intent, refs: refs, family: family}
	assessment, err := buildReliableSubmitAdmissionBinding(resolved, family, keys.key)
	if err != nil {
		return verifiedOperationalOriginal{}, errPrivateReplayUnavailable
	}
	encoded, err := encodeOperationalOriginal(delivery, resolved, assessment, keys, realm)
	if err != nil || !hmac.Equal(encoded, wire) {
		return verifiedOperationalOriginal{}, errPrivateReplayUnavailable
	}
	return verifiedOperationalOriginal{delivery: delivery, resolved: resolved, assessment: assessment, wire: encoded}, nil
}
