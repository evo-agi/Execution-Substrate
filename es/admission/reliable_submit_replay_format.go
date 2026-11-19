package admission

import (
	"bytes"
	"encoding/binary"
	"sort"
	"unicode/utf8"

	"execution-substrate/es/admission/internal/reliablesubmit"
)

type privateReplayField struct {
	id      uint16
	present bool
	value   []byte
}
type privateReplayEncoder struct {
	privateExecutionValue
	err error
}

func (e *privateReplayEncoder) field(id uint16, value []byte) privateReplayField {
	return privateReplayField{id: id, present: true, value: value}
}
func (e *privateReplayEncoder) optional(id uint16, present bool, value []byte) privateReplayField {
	return privateReplayField{id: id, present: present, value: value}
}

func (e *privateReplayEncoder) object(fields ...privateReplayField) []byte {
	if e.err != nil {
		return nil
	}
	if len(fields) > 65535 {
		e.err = errPrivateReplayInvalidDelivery
		return nil
	}
	length := 2
	for i, field := range fields {
		if field.id != uint16(i+1) || (!field.present && len(field.value) != 0) || len(field.value) > 1<<20 || length > 1<<20-7-len(field.value) {
			e.err = errPrivateReplayInvalidDelivery
			return nil
		}
		length += 7 + len(field.value)
	}
	out := make([]byte, length)
	binary.BigEndian.PutUint16(out[:2], uint16(len(fields)))
	offset := 2
	for _, field := range fields {
		binary.BigEndian.PutUint16(out[offset:offset+2], field.id)
		if field.present {
			out[offset+2] = 1
		}
		binary.BigEndian.PutUint32(out[offset+3:offset+7], uint32(len(field.value)))
		copy(out[offset+7:], field.value)
		offset += 7 + len(field.value)
	}
	return out
}

func (e *privateReplayEncoder) sequence(items [][]byte, max int) []byte {
	if e.err != nil {
		return nil
	}
	if len(items) > max || len(items) > 65535 {
		e.err = errPrivateReplayInvalidDelivery
		return nil
	}
	length := 2
	for _, item := range items {
		if len(item) > 1<<20 || length > 1<<20-4-len(item) {
			e.err = errPrivateReplayInvalidDelivery
			return nil
		}
		length += 4 + len(item)
	}
	out := make([]byte, length)
	binary.BigEndian.PutUint16(out[:2], uint16(len(items)))
	offset := 2
	for _, item := range items {
		binary.BigEndian.PutUint32(out[offset:offset+4], uint32(len(item)))
		copy(out[offset+4:], item)
		offset += 4 + len(item)
	}
	return out
}

func (e *privateReplayEncoder) string(value string, max int) []byte {
	if e.err != nil {
		return nil
	}
	if len(value) > max || !utf8.ValidString(value) {
		e.err = errPrivateReplayInvalidDelivery
		return nil
	}
	return []byte(value)
}

func (e *privateReplayEncoder) bytes(value []byte, max int) []byte {
	if e.err != nil {
		return nil
	}
	if len(value) > max {
		e.err = errPrivateReplayInvalidDelivery
		return nil
	}
	return append([]byte(nil), value...)
}

func (e *privateReplayEncoder) stringMap(value map[string]string, maxCount int) []byte {
	if e.err != nil {
		return nil
	}
	if len(value) > maxCount {
		e.err = errPrivateReplayInvalidDelivery
		return nil
	}
	keys := make([]string, 0, len(value))
	for key := range value {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return bytes.Compare([]byte(keys[i]), []byte(keys[j])) < 0 })
	length := 2
	for _, key := range keys {
		v := value[key]
		if len(key) > 1024 || len(v) > 65536 || !utf8.ValidString(key) || !utf8.ValidString(v) || length > 1<<20-6-len(key)-len(v) {
			e.err = errPrivateReplayInvalidDelivery
			return nil
		}
		length += 6 + len(key) + len(v)
	}
	out := make([]byte, length)
	binary.BigEndian.PutUint16(out[:2], uint16(len(keys)))
	offset := 2
	for _, key := range keys {
		v := value[key]
		binary.BigEndian.PutUint16(out[offset:offset+2], uint16(len(key)))
		offset += 2
		copy(out[offset:], key)
		offset += len(key)
		binary.BigEndian.PutUint32(out[offset:offset+4], uint32(len(v)))
		offset += 4
		copy(out[offset:], v)
		offset += len(v)
	}
	return out
}

func replayUint16(v uint16) []byte {
	var raw [2]byte
	binary.BigEndian.PutUint16(raw[:], v)
	return raw[:]
}
func replayUint32(v uint32) []byte {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], v)
	return raw[:]
}
func replayUint64(v uint64) []byte {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], v)
	return raw[:]
}
func replayInt64(v int64) []byte { return replayUint64(uint64(v)) }
func replayBool(v bool) []byte {
	if v {
		return []byte{1}
	}
	return []byte{0}
}

func (e *privateReplayEncoder) original(intent privateReplayOriginalIntent) []byte {
	argv := make([][]byte, 0, len(intent.argv.value))
	for _, arg := range intent.argv.value {
		argv = append(argv, e.string(arg, 65536))
	}
	mounts := make([][]byte, 0, len(intent.mounts.value))
	for _, mount := range intent.mounts.value {
		source := e.object(e.field(1, e.string(mount.artifactDigest, 256)))
		mounts = append(mounts, e.object(
			e.field(1, source), e.field(2, e.string(mount.targetPath, 4096)),
			e.optional(3, mount.readOnly.present, func() []byte {
				if mount.readOnly.present {
					return replayBool(mount.readOnly.value)
				}
				return nil
			}()),
		))
	}
	var resources []byte
	if intent.resources.present {
		resources = e.object(e.field(1, replayUint32(uint32(intent.resources.value.CPU))), e.field(2, replayUint32(uint32(intent.resources.value.MemoryMB))))
	}
	var profile []byte
	if intent.profile.present {
		profile = e.string(intent.profile.value, 65536)
	}
	return e.object(
		e.field(1, e.string(intent.outerSchema, 64)), e.field(2, e.string(intent.contract, 64)),
		e.field(3, []byte{1}), e.optional(4, intent.invocationSchema.present, e.string(intent.invocationSchema.value, 64)),
		e.field(5, e.string(intent.artifactDigest, 256)), e.field(6, e.string(intent.derivationDigest, 256)),
		e.field(7, e.string(intent.outputID, 256)), e.optional(8, intent.mode.present, e.string(intent.mode.value, 32)),
		e.optional(9, intent.timeout.present, func() []byte {
			if intent.timeout.present {
				return replayUint32(intent.timeout.value)
			}
			return nil
		}()),
		e.optional(10, intent.resources.present, resources),
		e.optional(11, intent.argv.present, func() []byte {
			if intent.argv.present {
				return e.sequence(argv, 100)
			}
			return nil
		}()),
		e.optional(12, intent.env.present, func() []byte {
			if intent.env.present {
				return e.stringMap(intent.env.value, 128)
			}
			return nil
		}()),
		e.optional(13, intent.mounts.present, func() []byte {
			if intent.mounts.present {
				return e.sequence(mounts, 8)
			}
			return nil
		}()),
		e.optional(14, intent.annotations.present, func() []byte {
			if intent.annotations.present {
				return e.stringMap(intent.annotations.value, 128)
			}
			return nil
		}()),
		e.optional(15, intent.profile.present, profile),
	)
}

func (e *privateReplayEncoder) plan(plan resolvedExecutionPlan) []byte {
	args := make([][]byte, 0, len(plan.runtimeCommand.arguments))
	for _, arg := range plan.runtimeCommand.arguments {
		args = append(args, e.string(arg, 65536))
	}
	mounts := make([][]byte, 0, len(plan.mounts))
	for _, mount := range plan.mounts {
		mounts = append(mounts, e.object(
			e.field(1, e.string(mount.artifactDigest, 4096)),
			e.field(2, e.string(mount.verifiedArtifactDigest, 4096)),
			e.field(3, e.string(mount.payloadDigest, 4096)),
			e.field(4, e.string(mount.targetPath, 4096)), e.field(5, replayBool(mount.readOnly)),
		))
	}
	a := plan.authority
	authority := e.object(
		e.field(1, e.string(a.runtimeProfileName, 4096)),
		e.field(2, replayBool(a.codexCredential.applicable)),
		e.field(3, e.string(a.codexCredential.cliPath, 4096)),
		e.field(4, e.string(a.codexCredential.credentialSource, 4096)),
		e.field(5, e.string(a.codexCredential.vaultSecretPath, 4096)),
		e.field(6, e.string(a.codexCredential.vaultSecretField, 4096)),
		e.field(7, e.string(a.workloadVault.mode, 4096)),
		e.field(8, e.string(a.workloadVault.address, 4096)),
		e.field(9, e.string(a.workloadVault.authMount, 4096)),
		e.field(10, e.string(a.workloadVault.authRole, 4096)),
		e.field(11, e.string(a.workloadVault.jwtAudience, 4096)),
		e.field(12, e.string(a.workloadZoneVaultConfigDigest, 4096)),
		e.field(13, replayBool(a.trustMaterial.vaultCACert)),
		e.field(14, replayBool(a.trustMaterial.workloadTLSBundle)),
	)
	job := plan.jobEnvelope
	options := make([][]byte, 0, len(job.securityOptions))
	for _, option := range job.securityOptions {
		options = append(options, e.string(option, 4096))
	}
	jobObject := e.object(
		e.field(1, e.string(job.jobType, 64)), e.field(2, e.string(job.groupName, 64)),
		e.field(3, replayUint32(uint32(job.groupCount))), e.field(4, e.string(job.taskName, 64)),
		e.field(5, e.string(job.driver, 64)), e.field(6, e.string(job.user, 64)),
		e.field(7, replayBool(job.privileged)), e.field(8, e.sequence(options, 32)),
		e.field(9, replayUint32(uint32(job.restartPolicy.attempts))),
		e.field(10, e.string(job.restartPolicy.mode, 64)),
		e.field(11, replayInt64(job.restartPolicy.interval)),
		e.field(12, replayInt64(job.restartPolicy.delay)),
		e.field(13, replayUint32(uint32(job.reschedulePolicy.attempts))),
		e.field(14, replayBool(job.reschedulePolicy.unlimited)),
		e.field(15, replayInt64(job.reschedulePolicy.delay)),
		e.field(16, e.string(job.reschedulePolicy.delayFunction, 64)),
		e.field(17, replayInt64(job.reschedulePolicy.maxDelay)),
	)
	return e.object(
		e.field(1, e.object(e.field(1, e.string(plan.requestSchemaVersion, 64)), e.field(2, e.string(plan.invocationSchemaVersion, 64)))),
		e.field(2, e.object(e.field(1, e.string(string(plan.mode), 32)), e.field(2, replayUint32(uint32(plan.timeoutSeconds))))),
		e.field(3, e.object(e.field(1, replayUint32(uint32(plan.resources.cpu))), e.field(2, replayUint32(uint32(plan.resources.memoryMB))))),
		e.field(4, e.object(e.field(1, e.string(plan.runtimeProfile.name, 1024)), e.field(2, e.string(plan.runtimeProfile.image, 1024)))),
		e.field(5, e.object(e.field(1, e.string(plan.artifactDigest, 256)), e.field(2, e.string(plan.payloadDigest, 256)))),
		e.field(6, e.object(e.field(1, e.string(plan.derivationSpecDigest, 256)), e.field(2, e.string(plan.outputID, 256)))),
		e.field(7, e.object(e.field(1, e.string(plan.runtimeCommand.executable, 4096)), e.field(2, e.sequence(args, 112)))),
		e.field(8, e.stringMap(plan.semanticEnvironment, 160)), e.field(9, e.sequence(mounts, 8)),
		e.field(10, replayBool(plan.networkAccess)), e.field(11, authority),
		e.field(12, e.string(plan.runtimeSupportDigest, 256)),
		e.field(13, replayUint64(uint64(plan.runtimeIdentityTmpfsSize))),
		e.field(14, jobObject),
	)
}

func (e *privateReplayEncoder) material(material resolvedExecutionMaterial) []byte {
	mounts := make([][]byte, 0, len(material.mounts))
	for _, archive := range material.mounts {
		entries := make([][]byte, 0, len(archive.entries))
		for _, entry := range archive.entries {
			entries = append(entries, e.object(
				e.field(1, e.string(entry.name, 4096)), e.field(2, replayBool(entry.directory)),
				e.field(3, replayUint32(uint32(entry.mode))),
				e.optional(4, !entry.directory, e.bytes(entry.contents, 262144)),
			))
		}
		mounts = append(mounts, e.object(e.field(1, e.bytes(archive.compressedBytes, 262144)), e.field(2, e.sequence(entries, 256))))
	}
	return e.object(
		e.field(1, e.bytes(material.payloadBytes, 262144)),
		e.field(2, e.bytes(material.runtimeSupportBytes, 262144)),
		e.field(3, e.sequence(mounts, 8)),
		e.optional(4, len(material.trust.vaultCACertBytes) > 0, e.bytes(material.trust.vaultCACertBytes, 262144)),
		e.optional(5, len(material.trust.workloadTLSBundleBytes) > 0, e.bytes(material.trust.workloadTLSBundleBytes, 262144)),
	)
}

func (e *privateReplayEncoder) descriptor(d bindingMaterialDescriptor) []byte {
	if d.state > 2 || d.length < 0 {
		e.err = errPrivateReplayInvalidDelivery
		return nil
	}
	out := make([]byte, 41)
	out[0] = d.state
	binary.BigEndian.PutUint64(out[1:9], uint64(d.length))
	copy(out[9:], d.digest[:])
	return out
}

func (e *privateReplayEncoder) materialIdentities(material bindingMaterialIdentities) []byte {
	mounts := make([][]byte, 0, len(material.mounts))
	for _, mount := range material.mounts {
		entries := make([][]byte, 0, len(mount.entries))
		for _, entry := range mount.entries {
			entries = append(entries, e.object(e.field(1, e.string(entry.name, 4096)), e.field(2, replayBool(entry.directory)),
				e.field(3, replayUint32(entry.mode)), e.field(4, e.descriptor(entry.content))))
		}
		mounts = append(mounts, e.object(
			e.field(1, e.string(mount.requestedArtifactDigest, 256)),
			e.field(2, e.string(mount.verifiedArtifactDigest, 256)),
			e.field(3, e.string(mount.payloadDigest, 256)),
			e.field(4, e.descriptor(mount.compressed)),
			e.field(5, e.sequence(entries, 256)),
		))
	}
	return e.object(e.field(1, e.descriptor(material.primary)), e.field(2, e.descriptor(material.support)),
		e.field(3, e.sequence(mounts, 8)), e.field(4, e.descriptor(material.vaultCA)), e.field(5, e.descriptor(material.tls)))
}

type privateSyntheticImagePlacement struct {
	privateExecutionValue
	contentDigest [32]byte
	issuer        string
}

func newPrivateSyntheticImagePlacement(contentDigest []byte, issuer string) (privateSyntheticImagePlacement, error) {
	if len(contentDigest) != 32 || issuer == "" || len(issuer) > 1024 || !utf8.ValidString(issuer) {
		return privateSyntheticImagePlacement{}, errPrivateReplayInvalidDelivery
	}
	var result privateSyntheticImagePlacement
	copy(result.contentDigest[:], contentDigest)
	result.issuer = issuer
	return result, nil
}

func (e *privateReplayEncoder) image(plan resolvedExecutionPlan, host hostMaterializationContext, image privateSyntheticImagePlacement) []byte {
	return e.object(e.field(1, e.string(plan.runtimeProfile.image, 1024)),
		e.field(2, image.contentDigest[:]), e.field(3, e.string(image.issuer, 1024)),
		e.field(4, []byte{1}), e.field(5, e.string(host.datacenter, 4096)))
}

func (e *privateReplayEncoder) placement(resolved resolvedExecution) []byte {
	host := resolved.host
	if host.owner.UID < 0 || host.owner.GID < 0 || uint64(host.owner.UID) > 4294967295 || uint64(host.owner.GID) > 4294967295 {
		e.err = errPrivateReplayInvalidDelivery
		return nil
	}
	return e.object(e.field(1, e.string(resolved.custodyPlacement.stagingRootDir, 4096)),
		e.field(2, e.string(resolved.custodyPlacement.resultsRootDir, 4096)),
		e.field(3, e.string(host.spireSourceDir, 4096)), e.field(4, e.string(host.datacenter, 4096)),
		e.field(5, replayUint32(uint32(host.owner.UID))), e.field(6, replayUint32(uint32(host.owner.GID))))
}

func (e *privateReplayEncoder) provenance(resolved resolvedExecution, scope byte) []byte {
	plan := resolved.plan
	mounts := make([][]byte, 0, len(plan.mounts))
	for _, mount := range plan.mounts {
		mounts = append(mounts, e.object(
			e.field(1, e.string(mount.artifactDigest, 256)), e.field(2, e.string(mount.verifiedArtifactDigest, 256)),
			e.field(3, e.string(mount.payloadDigest, 256))))
	}
	flags := e.object(e.field(1, replayBool(plan.authority.trustMaterial.vaultCACert)),
		e.field(2, replayBool(plan.authority.trustMaterial.workloadTLSBundle)))
	label := "synthetic_signed_dependencies_v1"
	if scope == 2 {
		label = "synthetic_progress_nonoperational_v1"
	}
	return e.object(e.field(1, []byte(label)),
		e.field(2, e.string(plan.artifactDigest, 256)), e.field(3, e.string(plan.payloadDigest, 256)),
		e.field(4, e.string(plan.runtimeSupportDigest, 256)), e.field(5, e.sequence(mounts, 8)), e.field(6, flags))
}

func (e *privateReplayEncoder) keys(bindingID, envelopeID string, scope byte) []byte {
	return e.object(e.field(1, replayUint16(1)), e.field(2, e.string(bindingID, 64)), e.field(3, e.string(envelopeID, 64)),
		e.field(4, replayUint16(uint16(scope))), e.field(5, replayUint16(uint16(scope))), e.field(6, replayUint16(1)))
}

func encodePrivateReplayPayload(delivery privateReplayDelivery, resolved resolvedExecution, assessment admissionBindingAssessment, image privateSyntheticImagePlacement, bindingID, envelopeID string, scope byte) ([]byte, error) {
	e := privateReplayEncoder{}
	identity, err := reliablesubmit.EncodePrivateReplayIdentity(delivery.refs.claimID)
	if err != nil {
		return nil, errPrivateReplayInvalidDelivery
	}
	materialIDs := e.materialIdentities(assessment.material)
	assessmentBytes, err := reliablesubmit.EncodePrivateReplayAssessment(assessment.boundPlan, materialIDs)
	if err != nil {
		return nil, errPrivateReplayInvalidDelivery
	}
	body := e.object(
		e.field(1, identity), e.field(2, e.original(delivery.originalIntent)),
		e.field(3, e.plan(resolved.plan)), e.field(4, e.material(resolved.material)),
		e.field(5, assessmentBytes), e.field(6, e.image(resolved.plan, resolved.host, image)),
		e.field(7, e.placement(resolved)), e.field(8, e.provenance(resolved, scope)),
		e.field(9, e.keys(bindingID, envelopeID, scope)), e.field(10, []byte{scope}),
	)
	if e.err != nil || len(body)+14 > 1<<20 {
		return nil, errPrivateReplayInvalidDelivery
	}
	return framePrivateReplayPayload(body, scope)
}

func privateReplayPayloadMagic(scope byte) string {
	switch scope {
	case 1:
		return "ESRSPAY1"
	case 2:
		return "ESRSPAY2"
	default:
		return ""
	}
}

func framePrivateReplayPayload(body []byte, scope byte) ([]byte, error) {
	magic := privateReplayPayloadMagic(scope)
	if magic == "" || len(body) < 2 || len(body) > 1<<20-14 {
		return nil, errPrivateReplayInvalidDelivery
	}
	out := make([]byte, 14+len(body))
	copy(out, magic)
	binary.BigEndian.PutUint16(out[8:10], uint16(scope))
	binary.BigEndian.PutUint32(out[10:14], uint32(len(body)))
	copy(out[14:], body)
	return out, nil
}
