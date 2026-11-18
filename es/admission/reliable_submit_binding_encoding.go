package admission

import (
	"crypto/sha256"
	"encoding/binary"
	"io"
	"sort"
	"unicode/utf8"
)

const (
	bindingTagString byte = 1
	bindingTagI64    byte = 2
	bindingTagBool   byte = 3
	bindingTagRecord byte = 4
	bindingTagSeq    byte = 5
	bindingTagMap    byte = 6
	bindingTagSHA256 byte = 7
	bindingTagState  byte = 8

	bindingStateAbsent       byte = 0
	bindingStatePresent      byte = 1
	bindingStateInapplicable byte = 2
)

type bindingEncoder struct {
	privateExecutionValue
	writer io.Writer
	used   int64
}

type bindingRecordKind byte

const (
	bindingFamilyRecord bindingRecordKind = iota + 1
	bindingProfileRecord
	bindingPrimaryRecord
	bindingCommandRecord
	bindingMountRecord
	bindingEntryRecord
	bindingAuthorityRecord
	bindingCodexRecord
	bindingVaultRecord
	bindingTrustFlagsRecord
	bindingSupportRecord
	bindingJobRecord
	bindingRestartRecord
	bindingRescheduleRecord
	bindingTrustRecord
)

func bindingCheckedAdd(current, addition, limit int64) (int64, bool) {
	if current < 0 || addition < 0 || limit < 0 || current > limit || addition > limit-current {
		return 0, false
	}
	return current + addition, true
}

func (encoder *bindingEncoder) fieldHeader(id uint16, tag byte, length int64) (bool, error) {
	if id == 0 || length < 0 {
		return false, bindingInputTooLarge()
	}
	needed, ok := bindingCheckedAdd(11, length, privateBindingCanonicalLimit)
	if !ok {
		return false, bindingInputTooLarge()
	}
	end, ok := bindingCheckedAdd(encoder.used, needed, privateBindingCanonicalLimit)
	if !ok {
		return false, bindingInputTooLarge()
	}
	if encoder.writer == nil {
		encoder.used = end
		return false, nil
	}
	var header [11]byte
	binary.BigEndian.PutUint16(header[:2], id)
	header[2] = tag
	binary.BigEndian.PutUint64(header[3:], uint64(length))
	if err := encoder.writeBytes(header[:]); err != nil {
		return false, err
	}
	return true, nil
}

func (encoder *bindingEncoder) writeBytes(content []byte) error {
	end, ok := bindingCheckedAdd(encoder.used, int64(len(content)), privateBindingCanonicalLimit)
	if !ok {
		return bindingInputTooLarge()
	}
	if encoder.writer != nil {
		written, err := encoder.writer.Write(content)
		if err != nil || written != len(content) {
			return bindingInvalidFacts()
		}
	}
	encoder.used = end
	return nil
}

// String chunks bound temporary conversion memory even for one large private
// environment value. No canonical message buffer is retained.
func (encoder *bindingEncoder) writeString(content string) error {
	for offset := 0; offset < len(content); {
		end := offset + 32*1024
		if end > len(content) {
			end = len(content)
		}
		if err := encoder.writeBytes([]byte(content[offset:end])); err != nil {
			return err
		}
		offset = end
	}
	return nil
}

func (encoder *bindingEncoder) writeUint64(value uint64) error {
	var content [8]byte
	binary.BigEndian.PutUint64(content[:], value)
	return encoder.writeBytes(content[:])
}

func bindingEmitString(encoder *bindingEncoder, id uint16, value string) error {
	addition, ok := bindingCheckedAdd(11, int64(len(value)), privateBindingCanonicalLimit)
	if !ok {
		return bindingInputTooLarge()
	}
	if _, ok := bindingCheckedAdd(encoder.used, addition, privateBindingCanonicalLimit); !ok {
		return bindingInputTooLarge()
	}
	if !utf8.ValidString(value) {
		return bindingInvalidFacts()
	}
	active, err := encoder.fieldHeader(id, bindingTagString, int64(len(value)))
	if err != nil || !active {
		return err
	}
	return encoder.writeString(value)
}

func bindingEmitI64(encoder *bindingEncoder, id uint16, value int64) error {
	active, err := encoder.fieldHeader(id, bindingTagI64, 8)
	if err != nil || !active {
		return err
	}
	return encoder.writeUint64(uint64(value))
}

func bindingEmitBool(encoder *bindingEncoder, id uint16, value bool) error {
	active, err := encoder.fieldHeader(id, bindingTagBool, 1)
	if err != nil || !active {
		return err
	}
	byteValue := byte(0)
	if value {
		byteValue = 1
	}
	return encoder.writeBytes([]byte{byteValue})
}

func bindingEmitState(encoder *bindingEncoder, id uint16, state byte) error {
	if state > bindingStateInapplicable {
		return bindingInvalidFacts()
	}
	active, err := encoder.fieldHeader(id, bindingTagState, 1)
	if err != nil || !active {
		return err
	}
	return encoder.writeBytes([]byte{state})
}

func bindingEmitDigestOfBytes(encoder *bindingEncoder, id uint16, content []byte) error {
	active, err := encoder.fieldHeader(id, bindingTagSHA256, sha256.Size)
	if err != nil || !active {
		return err
	}
	sum := sha256.Sum256(content)
	return encoder.writeBytes(sum[:])
}

func bindingEmitMaterialDescriptor(encoder *bindingEncoder, id uint16, state byte, content []byte) error {
	if state > bindingStateInapplicable {
		return bindingInvalidFacts()
	}
	payloadLength := int64(12)
	if state == bindingStatePresent {
		var ok bool
		payloadLength, ok = bindingCheckedAdd(payloadLength, 19+43, privateBindingCanonicalLimit)
		if !ok {
			return bindingInputTooLarge()
		}
	}
	active, err := encoder.fieldHeader(id, bindingTagRecord, payloadLength)
	if err != nil || !active {
		return err
	}
	start := encoder.used
	if err := bindingEmitState(encoder, 1, state); err != nil {
		return err
	}
	if state == bindingStatePresent {
		if err := bindingEmitI64(encoder, 2, int64(len(content))); err != nil {
			return err
		}
		if err := bindingEmitDigestOfBytes(encoder, 3, content); err != nil {
			return err
		}
	}
	if encoder.used-start != payloadLength {
		return bindingInvalidFacts()
	}
	return nil
}

func bindingMeasureRecord(kind bindingRecordKind, resolved resolvedExecution, family reliableBindingFamily, mountIndex, entryIndex int) (int64, error) {
	counter := bindingEncoder{}
	if err := bindingRecordFields(&counter, kind, resolved, family, mountIndex, entryIndex); err != nil {
		return 0, err
	}
	return counter.used, nil
}

func bindingEmitRecord(encoder *bindingEncoder, id uint16, kind bindingRecordKind, resolved resolvedExecution, family reliableBindingFamily, mountIndex, entryIndex int) error {
	length, err := bindingMeasureRecord(kind, resolved, family, mountIndex, entryIndex)
	if err != nil {
		return err
	}
	active, err := encoder.fieldHeader(id, bindingTagRecord, length)
	if err != nil || !active {
		return err
	}
	start := encoder.used
	if err := bindingRecordFields(encoder, kind, resolved, family, mountIndex, entryIndex); err != nil {
		return err
	}
	if encoder.used-start != length {
		return bindingInvalidFacts()
	}
	return nil
}

func bindingRecordFields(encoder *bindingEncoder, kind bindingRecordKind, resolved resolvedExecution, family reliableBindingFamily, mountIndex, entryIndex int) error {
	plan := resolved.plan
	switch kind {
	case bindingFamilyRecord:
		if err := bindingEmitString(encoder, 1, family.schemaVersion); err != nil {
			return err
		}
		if err := bindingEmitString(encoder, 2, family.contract); err != nil {
			return err
		}
		if err := bindingEmitString(encoder, 3, plan.requestSchemaVersion); err != nil {
			return err
		}
		return bindingEmitString(encoder, 4, plan.invocationSchemaVersion)
	case bindingProfileRecord:
		if err := bindingEmitString(encoder, 1, plan.runtimeProfile.name); err != nil {
			return err
		}
		return bindingEmitString(encoder, 2, plan.runtimeProfile.image)
	case bindingPrimaryRecord:
		if err := bindingEmitString(encoder, 1, plan.artifactDigest); err != nil {
			return err
		}
		if err := bindingEmitString(encoder, 2, plan.payloadDigest); err != nil {
			return err
		}
		return bindingEmitMaterialDescriptor(encoder, 3, bindingStatePresent, resolved.material.payloadBytes)
	case bindingCommandRecord:
		if err := bindingEmitString(encoder, 1, plan.runtimeCommand.executable); err != nil {
			return err
		}
		return bindingEmitStringSequence(encoder, 2, plan.runtimeCommand.arguments)
	case bindingMountRecord:
		mount, archive := plan.mounts[mountIndex], resolved.material.mounts[mountIndex]
		if err := bindingEmitString(encoder, 1, mount.artifactDigest); err != nil {
			return err
		}
		if err := bindingEmitString(encoder, 2, mount.verifiedArtifactDigest); err != nil {
			return err
		}
		if err := bindingEmitString(encoder, 3, mount.payloadDigest); err != nil {
			return err
		}
		if err := bindingEmitString(encoder, 4, mount.targetPath); err != nil {
			return err
		}
		if err := bindingEmitBool(encoder, 5, mount.readOnly); err != nil {
			return err
		}
		if err := bindingEmitMaterialDescriptor(encoder, 6, bindingStatePresent, archive.compressedBytes); err != nil {
			return err
		}
		return bindingEmitEntrySequence(encoder, 7, resolved, family, mountIndex)
	case bindingEntryRecord:
		entry := resolved.material.mounts[mountIndex].entries[entryIndex]
		if err := bindingEmitString(encoder, 1, entry.name); err != nil {
			return err
		}
		kindName := "regular"
		if entry.directory {
			kindName = "directory"
		}
		if err := bindingEmitString(encoder, 2, kindName); err != nil {
			return err
		}
		if err := bindingEmitI64(encoder, 3, int64(entry.mode)); err != nil {
			return err
		}
		state := bindingStatePresent
		if entry.directory {
			state = bindingStateInapplicable
		}
		return bindingEmitMaterialDescriptor(encoder, 4, state, entry.contents)
	case bindingAuthorityRecord:
		if err := bindingEmitState(encoder, 1, bindingStatePresent); err != nil {
			return err
		}
		if err := bindingEmitString(encoder, 2, plan.authority.runtimeProfileName); err != nil {
			return err
		}
		if err := bindingEmitRecord(encoder, 3, bindingCodexRecord, resolved, family, 0, 0); err != nil {
			return err
		}
		if err := bindingEmitRecord(encoder, 4, bindingVaultRecord, resolved, family, 0, 0); err != nil {
			return err
		}
		if err := bindingEmitString(encoder, 5, plan.authority.workloadZoneVaultConfigDigest); err != nil {
			return err
		}
		return bindingEmitRecord(encoder, 6, bindingTrustFlagsRecord, resolved, family, 0, 0)
	case bindingCodexRecord:
		location := plan.authority.codexCredential
		if !location.applicable {
			return bindingEmitState(encoder, 1, bindingStateInapplicable)
		}
		if err := bindingEmitState(encoder, 1, bindingStatePresent); err != nil {
			return err
		}
		if err := bindingEmitString(encoder, 2, location.cliPath); err != nil {
			return err
		}
		if err := bindingEmitString(encoder, 3, location.credentialSource); err != nil {
			return err
		}
		if err := bindingEmitString(encoder, 4, location.vaultSecretPath); err != nil {
			return err
		}
		return bindingEmitString(encoder, 5, location.vaultSecretField)
	case bindingVaultRecord:
		vault := plan.authority.workloadVault
		if err := bindingEmitString(encoder, 1, vault.mode); err != nil {
			return err
		}
		if err := bindingEmitString(encoder, 2, vault.address); err != nil {
			return err
		}
		if err := bindingEmitString(encoder, 3, vault.authMount); err != nil {
			return err
		}
		if err := bindingEmitString(encoder, 4, vault.authRole); err != nil {
			return err
		}
		return bindingEmitString(encoder, 5, vault.jwtAudience)
	case bindingTrustFlagsRecord:
		if err := bindingEmitBool(encoder, 1, plan.authority.trustMaterial.vaultCACert); err != nil {
			return err
		}
		return bindingEmitBool(encoder, 2, plan.authority.trustMaterial.workloadTLSBundle)
	case bindingSupportRecord:
		if err := bindingEmitString(encoder, 1, plan.runtimeSupportDigest); err != nil {
			return err
		}
		return bindingEmitMaterialDescriptor(encoder, 2, bindingStatePresent, resolved.material.runtimeSupportBytes)
	case bindingJobRecord:
		job := plan.jobEnvelope
		if err := bindingEmitString(encoder, 1, job.jobType); err != nil {
			return err
		}
		if err := bindingEmitString(encoder, 2, job.groupName); err != nil {
			return err
		}
		if err := bindingEmitI64(encoder, 3, int64(job.groupCount)); err != nil {
			return err
		}
		if err := bindingEmitString(encoder, 4, job.taskName); err != nil {
			return err
		}
		if err := bindingEmitString(encoder, 5, job.driver); err != nil {
			return err
		}
		if err := bindingEmitString(encoder, 6, job.user); err != nil {
			return err
		}
		if err := bindingEmitBool(encoder, 7, job.privileged); err != nil {
			return err
		}
		if err := bindingEmitStringSequence(encoder, 8, job.securityOptions); err != nil {
			return err
		}
		if err := bindingEmitRecord(encoder, 9, bindingRestartRecord, resolved, family, 0, 0); err != nil {
			return err
		}
		return bindingEmitRecord(encoder, 10, bindingRescheduleRecord, resolved, family, 0, 0)
	case bindingRestartRecord:
		restart := plan.jobEnvelope.restartPolicy
		if err := bindingEmitI64(encoder, 1, int64(restart.attempts)); err != nil {
			return err
		}
		if err := bindingEmitString(encoder, 2, restart.mode); err != nil {
			return err
		}
		if err := bindingEmitI64(encoder, 3, restart.interval); err != nil {
			return err
		}
		return bindingEmitI64(encoder, 4, restart.delay)
	case bindingRescheduleRecord:
		reschedule := plan.jobEnvelope.reschedulePolicy
		if err := bindingEmitI64(encoder, 1, int64(reschedule.attempts)); err != nil {
			return err
		}
		if err := bindingEmitBool(encoder, 2, reschedule.unlimited); err != nil {
			return err
		}
		if err := bindingEmitI64(encoder, 3, reschedule.delay); err != nil {
			return err
		}
		if err := bindingEmitString(encoder, 4, reschedule.delayFunction); err != nil {
			return err
		}
		return bindingEmitI64(encoder, 5, reschedule.maxDelay)
	case bindingTrustRecord:
		vaultState := bindingStateAbsent
		if len(resolved.material.trust.vaultCACertBytes) > 0 {
			vaultState = bindingStatePresent
		}
		tlsState := bindingStateAbsent
		if len(resolved.material.trust.workloadTLSBundleBytes) > 0 {
			tlsState = bindingStatePresent
		}
		if err := bindingEmitMaterialDescriptor(encoder, 1, vaultState, resolved.material.trust.vaultCACertBytes); err != nil {
			return err
		}
		return bindingEmitMaterialDescriptor(encoder, 2, tlsState, resolved.material.trust.workloadTLSBundleBytes)
	}
	return bindingInvalidFacts()
}

func bindingEmitStringSequence(encoder *bindingEncoder, id uint16, values []string) error {
	length := int64(8)
	for _, value := range values {
		addition, ok := bindingCheckedAdd(8, int64(len(value)), privateBindingCanonicalLimit)
		if !ok {
			return bindingInputTooLarge()
		}
		length, ok = bindingCheckedAdd(length, addition, privateBindingCanonicalLimit)
		if !ok {
			return bindingInputTooLarge()
		}
	}
	fieldLength, ok := bindingCheckedAdd(11, length, privateBindingCanonicalLimit)
	if !ok {
		return bindingInputTooLarge()
	}
	if _, ok := bindingCheckedAdd(encoder.used, fieldLength, privateBindingCanonicalLimit); !ok {
		return bindingInputTooLarge()
	}
	for _, value := range values {
		if !utf8.ValidString(value) {
			return bindingInvalidFacts()
		}
	}
	active, err := encoder.fieldHeader(id, bindingTagSeq, length)
	if err != nil || !active {
		return err
	}
	start := encoder.used
	if err := encoder.writeUint64(uint64(len(values))); err != nil {
		return err
	}
	for _, value := range values {
		if err := encoder.writeUint64(uint64(len(value))); err != nil {
			return err
		}
		if err := encoder.writeString(value); err != nil {
			return err
		}
	}
	if encoder.used-start != length {
		return bindingInvalidFacts()
	}
	return nil
}

func bindingEmitMountSequence(encoder *bindingEncoder, id uint16, resolved resolvedExecution, family reliableBindingFamily) error {
	length := int64(8)
	for index := range resolved.plan.mounts {
		elementLength, err := bindingMeasureRecord(bindingMountRecord, resolved, family, index, 0)
		if err != nil {
			return err
		}
		addition, ok := bindingCheckedAdd(8, elementLength, privateBindingCanonicalLimit)
		if !ok {
			return bindingInputTooLarge()
		}
		length, ok = bindingCheckedAdd(length, addition, privateBindingCanonicalLimit)
		if !ok {
			return bindingInputTooLarge()
		}
	}
	active, err := encoder.fieldHeader(id, bindingTagSeq, length)
	if err != nil || !active {
		return err
	}
	start := encoder.used
	if err := encoder.writeUint64(uint64(len(resolved.plan.mounts))); err != nil {
		return err
	}
	for index := range resolved.plan.mounts {
		elementLength, err := bindingMeasureRecord(bindingMountRecord, resolved, family, index, 0)
		if err != nil {
			return err
		}
		if err := encoder.writeUint64(uint64(elementLength)); err != nil {
			return err
		}
		before := encoder.used
		if err := bindingRecordFields(encoder, bindingMountRecord, resolved, family, index, 0); err != nil {
			return err
		}
		if encoder.used-before != elementLength {
			return bindingInvalidFacts()
		}
	}
	if encoder.used-start != length {
		return bindingInvalidFacts()
	}
	return nil
}

func bindingEmitEntrySequence(encoder *bindingEncoder, id uint16, resolved resolvedExecution, family reliableBindingFamily, mountIndex int) error {
	entries := resolved.material.mounts[mountIndex].entries
	length := int64(8)
	for index := range entries {
		elementLength, err := bindingMeasureRecord(bindingEntryRecord, resolved, family, mountIndex, index)
		if err != nil {
			return err
		}
		addition, ok := bindingCheckedAdd(8, elementLength, privateBindingCanonicalLimit)
		if !ok {
			return bindingInputTooLarge()
		}
		length, ok = bindingCheckedAdd(length, addition, privateBindingCanonicalLimit)
		if !ok {
			return bindingInputTooLarge()
		}
	}
	active, err := encoder.fieldHeader(id, bindingTagSeq, length)
	if err != nil || !active {
		return err
	}
	start := encoder.used
	if err := encoder.writeUint64(uint64(len(entries))); err != nil {
		return err
	}
	for index := range entries {
		elementLength, err := bindingMeasureRecord(bindingEntryRecord, resolved, family, mountIndex, index)
		if err != nil {
			return err
		}
		if err := encoder.writeUint64(uint64(elementLength)); err != nil {
			return err
		}
		before := encoder.used
		if err := bindingRecordFields(encoder, bindingEntryRecord, resolved, family, mountIndex, index); err != nil {
			return err
		}
		if encoder.used-before != elementLength {
			return bindingInvalidFacts()
		}
	}
	if encoder.used-start != length {
		return bindingInvalidFacts()
	}
	return nil
}

func bindingEmitMap(encoder *bindingEncoder, id uint16, values map[string]string) error {
	length := int64(8)
	for key, value := range values {
		addition, ok := bindingCheckedAdd(16, int64(len(key)), privateBindingCanonicalLimit)
		if !ok {
			return bindingInputTooLarge()
		}
		addition, ok = bindingCheckedAdd(addition, int64(len(value)), privateBindingCanonicalLimit)
		if !ok {
			return bindingInputTooLarge()
		}
		length, ok = bindingCheckedAdd(length, addition, privateBindingCanonicalLimit)
		if !ok {
			return bindingInputTooLarge()
		}
	}
	fieldLength, ok := bindingCheckedAdd(11, length, privateBindingCanonicalLimit)
	if !ok {
		return bindingInputTooLarge()
	}
	if _, ok := bindingCheckedAdd(encoder.used, fieldLength, privateBindingCanonicalLimit); !ok {
		return bindingInputTooLarge()
	}
	for key, value := range values {
		if !utf8.ValidString(key) || !utf8.ValidString(value) {
			return bindingInvalidFacts()
		}
	}
	active, err := encoder.fieldHeader(id, bindingTagMap, length)
	if err != nil || !active {
		return err
	}
	// The complete canonical size is checked by the prior counted pass before
	// this map key slice is allocated or sorted.
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	start := encoder.used
	if err := encoder.writeUint64(uint64(len(keys))); err != nil {
		return err
	}
	for _, key := range keys {
		value := values[key]
		if err := encoder.writeUint64(uint64(len(key))); err != nil {
			return err
		}
		if err := encoder.writeString(key); err != nil {
			return err
		}
		if err := encoder.writeUint64(uint64(len(value))); err != nil {
			return err
		}
		if err := encoder.writeString(value); err != nil {
			return err
		}
	}
	if encoder.used-start != length {
		return bindingInvalidFacts()
	}
	return nil
}

func bindingEncodeCanonical(encoder *bindingEncoder, resolved resolvedExecution, family reliableBindingFamily) error {
	plan := resolved.plan
	if err := bindingEmitRecord(encoder, 1, bindingFamilyRecord, resolved, family, 0, 0); err != nil {
		return err
	}
	if err := bindingEmitString(encoder, 2, string(plan.mode)); err != nil {
		return err
	}
	if err := bindingEmitI64(encoder, 3, int64(plan.timeoutSeconds)); err != nil {
		return err
	}
	if err := bindingEmitI64(encoder, 4, int64(plan.resources.cpu)); err != nil {
		return err
	}
	if err := bindingEmitI64(encoder, 5, int64(plan.resources.memoryMB)); err != nil {
		return err
	}
	if err := bindingEmitRecord(encoder, 6, bindingProfileRecord, resolved, family, 0, 0); err != nil {
		return err
	}
	if err := bindingEmitRecord(encoder, 7, bindingPrimaryRecord, resolved, family, 0, 0); err != nil {
		return err
	}
	if err := bindingEmitString(encoder, 8, plan.derivationSpecDigest); err != nil {
		return err
	}
	if err := bindingEmitString(encoder, 9, plan.outputID); err != nil {
		return err
	}
	if err := bindingEmitRecord(encoder, 10, bindingCommandRecord, resolved, family, 0, 0); err != nil {
		return err
	}
	if err := bindingEmitMap(encoder, 11, plan.semanticEnvironment); err != nil {
		return err
	}
	if err := bindingEmitMountSequence(encoder, 12, resolved, family); err != nil {
		return err
	}
	if err := bindingEmitBool(encoder, 13, plan.networkAccess); err != nil {
		return err
	}
	if err := bindingEmitRecord(encoder, 14, bindingAuthorityRecord, resolved, family, 0, 0); err != nil {
		return err
	}
	if err := bindingEmitRecord(encoder, 15, bindingSupportRecord, resolved, family, 0, 0); err != nil {
		return err
	}
	if err := bindingEmitI64(encoder, 16, plan.runtimeIdentityTmpfsSize); err != nil {
		return err
	}
	if err := bindingEmitRecord(encoder, 17, bindingJobRecord, resolved, family, 0, 0); err != nil {
		return err
	}
	return bindingEmitRecord(encoder, 18, bindingTrustRecord, resolved, family, 0, 0)
}

func bindingMeasureCanonical(resolved resolvedExecution, family reliableBindingFamily) (int64, error) {
	// A malformed plan/material pairing must fail before record indexing.
	if len(resolved.plan.mounts) != len(resolved.material.mounts) {
		return 0, bindingInvalidFacts()
	}
	counter := bindingEncoder{}
	if err := bindingEncodeCanonical(&counter, resolved, family); err != nil {
		return 0, err
	}
	return counter.used, nil
}
