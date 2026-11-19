package admission

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"
	"os"
	"slices"
	"unicode/utf8"

	"execution-substrate/es/admission/internal/reliablesubmit"
)

type privateReplayReader struct {
	privateExecutionValue
	nodes    int
	elements int
}

func (r *privateReplayReader) object(raw []byte, count, objectDepth, containerDepth int) ([]privateReplayField, error) {
	if len(raw) < 2 || len(raw) > 1<<20 || objectDepth > 5 || containerDepth > 8 || count < 0 || count > 65535 || int(binary.BigEndian.Uint16(raw[:2])) != count || r.nodes > 32768-count {
		return nil, errPrivateReplayUnavailable
	}
	fields := make([]privateReplayField, count)
	offset := 2
	for i := 0; i < count; i++ {
		if len(raw)-offset < 7 {
			return nil, errPrivateReplayUnavailable
		}
		id := binary.BigEndian.Uint16(raw[offset : offset+2])
		state := raw[offset+2]
		length := binary.BigEndian.Uint32(raw[offset+3 : offset+7])
		offset += 7
		if id != uint16(i+1) || state > 1 || length > uint32(len(raw)-offset) || state == 0 && length != 0 {
			return nil, errPrivateReplayUnavailable
		}
		fields[i] = privateReplayField{id: id, present: state == 1, value: raw[offset : offset+int(length)]}
		offset += int(length)
	}
	if offset != len(raw) {
		return nil, errPrivateReplayUnavailable
	}
	r.nodes += count
	return fields, nil
}

func (r *privateReplayReader) sequence(raw []byte, max, depth int) ([][]byte, error) {
	if len(raw) < 2 || len(raw) > 1<<20 || depth > 8 {
		return nil, errPrivateReplayUnavailable
	}
	count := int(binary.BigEndian.Uint16(raw[:2]))
	if count > max || r.elements > 8192-count {
		return nil, errPrivateReplayUnavailable
	}
	r.elements += count
	result := make([][]byte, 0, count)
	offset := 2
	for range count {
		if len(raw)-offset < 4 {
			return nil, errPrivateReplayUnavailable
		}
		length := binary.BigEndian.Uint32(raw[offset : offset+4])
		offset += 4
		if length > uint32(len(raw)-offset) {
			return nil, errPrivateReplayUnavailable
		}
		result = append(result, raw[offset:offset+int(length)])
		offset += int(length)
	}
	if offset != len(raw) {
		return nil, errPrivateReplayUnavailable
	}
	return result, nil
}

func (r *privateReplayReader) stringMap(raw []byte, max, depth int) (map[string]string, error) {
	if len(raw) < 2 || len(raw) > 1<<20 || depth > 8 {
		return nil, errPrivateReplayUnavailable
	}
	count := int(binary.BigEndian.Uint16(raw[:2]))
	if count > max || r.elements > 8192-count {
		return nil, errPrivateReplayUnavailable
	}
	r.elements += count
	result := make(map[string]string, count)
	offset := 2
	var prior []byte
	for range count {
		if len(raw)-offset < 2 {
			return nil, errPrivateReplayUnavailable
		}
		keyLen := int(binary.BigEndian.Uint16(raw[offset : offset+2]))
		offset += 2
		if keyLen > 1024 || keyLen > len(raw)-offset {
			return nil, errPrivateReplayUnavailable
		}
		key := raw[offset : offset+keyLen]
		offset += keyLen
		if !utf8.Valid(key) || prior != nil && bytes.Compare(prior, key) >= 0 {
			return nil, errPrivateReplayUnavailable
		}
		if len(raw)-offset < 4 {
			return nil, errPrivateReplayUnavailable
		}
		valueLen := binary.BigEndian.Uint32(raw[offset : offset+4])
		offset += 4
		if valueLen > 65536 || valueLen > uint32(len(raw)-offset) {
			return nil, errPrivateReplayUnavailable
		}
		value := raw[offset : offset+int(valueLen)]
		offset += int(valueLen)
		if !utf8.Valid(value) {
			return nil, errPrivateReplayUnavailable
		}
		result[string(key)] = string(value)
		prior = key
	}
	if offset != len(raw) {
		return nil, errPrivateReplayUnavailable
	}
	return result, nil
}

func (r *privateReplayReader) required(fields []privateReplayField, id int) ([]byte, error) {
	if id < 1 || id > len(fields) || !fields[id-1].present {
		return nil, errPrivateReplayUnavailable
	}
	return fields[id-1].value, nil
}

func (r *privateReplayReader) string(fields []privateReplayField, id, max int) (string, error) {
	raw, err := r.required(fields, id)
	if err != nil || len(raw) > max || !utf8.Valid(raw) {
		return "", errPrivateReplayUnavailable
	}
	return string(raw), nil
}

func (r *privateReplayReader) optionalString(fields []privateReplayField, id, max int) (replayPresence[string], error) {
	if id < 1 || id > len(fields) {
		return replayPresence[string]{}, errPrivateReplayUnavailable
	}
	if !fields[id-1].present {
		return replayPresence[string]{}, nil
	}
	value, err := r.string(fields, id, max)
	if err != nil {
		return replayPresence[string]{}, err
	}
	return replayPresence[string]{true, value}, nil
}

func (r *privateReplayReader) uint(fields []privateReplayField, id, width int, max uint64) (uint64, error) {
	raw, err := r.required(fields, id)
	if err != nil || len(raw) != width {
		return 0, errPrivateReplayUnavailable
	}
	var value uint64
	switch width {
	case 1:
		value = uint64(raw[0])
	case 2:
		value = uint64(binary.BigEndian.Uint16(raw))
	case 4:
		value = uint64(binary.BigEndian.Uint32(raw))
	case 8:
		value = binary.BigEndian.Uint64(raw)
	default:
		return 0, errPrivateReplayUnavailable
	}
	if value > max {
		return 0, errPrivateReplayUnavailable
	}
	return value, nil
}

func (r *privateReplayReader) bool(fields []privateReplayField, id int) (bool, error) {
	value, err := r.uint(fields, id, 1, 1)
	return value == 1, err
}

func (r *privateReplayReader) strings(raw []byte, maxCount, maxBytes, depth int) ([]string, error) {
	items, err := r.sequence(raw, maxCount, depth)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		if len(item) > maxBytes || !utf8.Valid(item) {
			return nil, errPrivateReplayUnavailable
		}
		result = append(result, string(item))
	}
	return result, nil
}

func (r *privateReplayReader) original(raw []byte) (privateReplayOriginalIntent, error) {
	f, err := r.object(raw, 15, 2, 2)
	if err != nil {
		return privateReplayOriginalIntent{}, err
	}
	var intent privateReplayOriginalIntent
	intent.outerSchema, err = r.string(f, 1, 64)
	if err != nil || intent.outerSchema != reliableSubmitRequestSchemaV1 {
		return privateReplayOriginalIntent{}, errPrivateReplayUnavailable
	}
	intent.contract, err = r.string(f, 2, 64)
	if err != nil || intent.contract != reliableSubmitContractV1 {
		return privateReplayOriginalIntent{}, errPrivateReplayUnavailable
	}
	marker, err := r.uint(f, 3, 1, 1)
	if err != nil || marker != 1 {
		return privateReplayOriginalIntent{}, errPrivateReplayUnavailable
	}
	intent.invocationPresent = true
	intent.invocationSchema, err = r.optionalString(f, 4, 64)
	if err != nil {
		return privateReplayOriginalIntent{}, err
	}
	if intent.invocationSchema.present && intent.invocationSchema.value != "" && intent.invocationSchema.value != "v1" {
		return privateReplayOriginalIntent{}, errPrivateReplayUnavailable
	}
	intent.artifactDigest, err = r.string(f, 5, 256)
	if err != nil || intent.artifactDigest == "" {
		return privateReplayOriginalIntent{}, errPrivateReplayUnavailable
	}
	intent.derivationDigest, err = r.string(f, 6, 256)
	if err != nil || intent.derivationDigest == "" {
		return privateReplayOriginalIntent{}, errPrivateReplayUnavailable
	}
	intent.outputID, err = r.string(f, 7, 256)
	if err != nil || intent.outputID == "" {
		return privateReplayOriginalIntent{}, errPrivateReplayUnavailable
	}
	intent.mode, err = r.optionalString(f, 8, 32)
	if err != nil || intent.mode.present && intent.mode.value != "" && intent.mode.value != "async" {
		return privateReplayOriginalIntent{}, errPrivateReplayUnavailable
	}
	if f[8].present {
		value, e := r.uint(f, 9, 4, 2147483647)
		if e != nil {
			return privateReplayOriginalIntent{}, e
		}
		intent.timeout = replayPresence[uint32]{true, uint32(value)}
	}
	if f[9].present {
		resources, e := r.object(f[9].value, 2, 3, 3)
		if e != nil {
			return privateReplayOriginalIntent{}, e
		}
		cpu, e := r.uint(resources, 1, 4, 2147483647)
		if e != nil || cpu == 0 {
			return privateReplayOriginalIntent{}, errPrivateReplayUnavailable
		}
		memory, e := r.uint(resources, 2, 4, 2147483647)
		if e != nil || memory == 0 {
			return privateReplayOriginalIntent{}, errPrivateReplayUnavailable
		}
		intent.resources = replayPresence[ExecutionResources]{true, ExecutionResources{CPU: int(cpu), MemoryMB: int(memory)}}
	}
	if f[10].present {
		value, e := r.strings(f[10].value, 100, 65536, 3)
		if e != nil {
			return privateReplayOriginalIntent{}, e
		}
		intent.argv = replayPresence[[]string]{true, value}
	}
	if f[11].present {
		value, e := r.stringMap(f[11].value, 128, 3)
		if e != nil {
			return privateReplayOriginalIntent{}, e
		}
		intent.env = replayPresence[map[string]string]{true, value}
	}
	if f[12].present {
		items, e := r.sequence(f[12].value, 8, 3)
		if e != nil {
			return privateReplayOriginalIntent{}, e
		}
		mounts := make([]privateReplayOriginalMount, 0, len(items))
		for _, item := range items {
			mount, e := r.object(item, 3, 3, 4)
			if e != nil {
				return privateReplayOriginalIntent{}, e
			}
			source, e := r.object(mount[0].value, 1, 4, 5)
			if e != nil {
				return privateReplayOriginalIntent{}, e
			}
			artifact, e := r.string(source, 1, 256)
			if e != nil || artifact == "" {
				return privateReplayOriginalIntent{}, errPrivateReplayUnavailable
			}
			target, e := r.string(mount, 2, 4096)
			if e != nil {
				return privateReplayOriginalIntent{}, e
			}
			clean, e := normalizeRuntimeMountTargetPath(target)
			if e != nil || clean != target {
				return privateReplayOriginalIntent{}, errPrivateReplayUnavailable
			}
			entry := privateReplayOriginalMount{artifactDigest: artifact, targetPath: target}
			if mount[2].present {
				value, e := r.bool(mount, 3)
				if e != nil {
					return privateReplayOriginalIntent{}, e
				}
				entry.readOnly = replayPresence[bool]{true, value}
			}
			mounts = append(mounts, entry)
		}
		intent.mounts = replayPresence[[]privateReplayOriginalMount]{true, mounts}
	}
	if f[13].present {
		value, e := r.stringMap(f[13].value, 128, 3)
		if e != nil {
			return privateReplayOriginalIntent{}, e
		}
		intent.annotations = replayPresence[map[string]string]{true, value}
	}
	intent.profile, err = r.optionalString(f, 15, 65536)
	if err != nil {
		return privateReplayOriginalIntent{}, err
	}
	profile, profilePresent := intent.annotations.value[runtimeProfileAnnotationKey]
	if profilePresent != intent.profile.present || profilePresent && profile != intent.profile.value {
		return privateReplayOriginalIntent{}, errPrivateReplayUnavailable
	}
	return intent, nil
}

func (r *privateReplayReader) payload(raw []byte) ([]privateReplayField, error) {
	return r.scopedPayload(raw, 1)
}

func (r *privateReplayReader) scopedPayload(raw []byte, scope byte) ([]privateReplayField, error) {
	if len(raw) < 16 || len(raw) > 1<<20 || string(raw[:8]) != privateReplayPayloadMagic(scope) || binary.BigEndian.Uint16(raw[8:10]) != uint16(scope) || binary.BigEndian.Uint32(raw[10:14]) != uint32(len(raw)-14) {
		return nil, errPrivateReplayUnavailable
	}
	f, err := r.object(raw[14:], 10, 1, 1)
	if err != nil {
		return nil, err
	}
	for _, field := range f {
		if !field.present {
			return nil, errPrivateReplayUnavailable
		}
	}
	return f, nil
}

func (r *privateReplayReader) plan(raw []byte) (resolvedPlanFacts, error) {
	f, err := r.object(raw, 14, 2, 2)
	if err != nil {
		return resolvedPlanFacts{}, err
	}
	for _, field := range f {
		if !field.present {
			return resolvedPlanFacts{}, errPrivateReplayUnavailable
		}
	}
	var p resolvedPlanFacts
	group := func(id int) ([]privateReplayField, error) { return r.object(f[id-1].value, 2, 3, 3) }
	g, err := group(1)
	if err != nil {
		return p, err
	}
	p.requestSchemaVersion, err = r.string(g, 1, 64)
	if err != nil {
		return p, err
	}
	p.invocationSchemaVersion, err = r.string(g, 2, 64)
	if err != nil {
		return p, err
	}
	g, err = group(2)
	if err != nil {
		return p, err
	}
	mode, err := r.string(g, 1, 32)
	if err != nil || mode != "async" {
		return p, errPrivateReplayUnavailable
	}
	p.mode = ExecutionMode(mode)
	timeout, err := r.uint(g, 2, 4, 2147483647)
	if err != nil {
		return p, err
	}
	p.timeoutSeconds = int(timeout)
	g, err = group(3)
	if err != nil {
		return p, err
	}
	cpu, err := r.uint(g, 1, 4, 2147483647)
	if err != nil || cpu == 0 {
		return p, errPrivateReplayUnavailable
	}
	memory, err := r.uint(g, 2, 4, 2147483647)
	if err != nil || memory == 0 {
		return p, errPrivateReplayUnavailable
	}
	p.resources = resolvedTaskResources{cpu: int(cpu), memoryMB: int(memory)}
	g, err = group(4)
	if err != nil {
		return p, err
	}
	p.runtimeProfile.name, err = r.string(g, 1, 1024)
	if err != nil {
		return p, err
	}
	p.runtimeProfile.image, err = r.string(g, 2, 1024)
	if err != nil {
		return p, err
	}
	g, err = group(5)
	if err != nil {
		return p, err
	}
	p.artifactDigest, err = r.string(g, 1, 256)
	if err != nil {
		return p, err
	}
	p.payloadDigest, err = r.string(g, 2, 256)
	if err != nil {
		return p, err
	}
	g, err = group(6)
	if err != nil {
		return p, err
	}
	p.derivationSpecDigest, err = r.string(g, 1, 256)
	if err != nil {
		return p, err
	}
	p.outputID, err = r.string(g, 2, 256)
	if err != nil {
		return p, err
	}
	g, err = group(7)
	if err != nil {
		return p, err
	}
	p.runtimeCommand.executable, err = r.string(g, 1, 4096)
	if err != nil {
		return p, err
	}
	argsRaw, err := r.required(g, 2)
	if err != nil {
		return p, err
	}
	p.runtimeCommand.arguments, err = r.strings(argsRaw, 112, 65536, 4)
	if err != nil {
		return p, err
	}
	p.semanticEnvironment, err = r.stringMap(f[7].value, 160, 3)
	if err != nil {
		return p, err
	}
	mountsRaw, err := r.sequence(f[8].value, 8, 3)
	if err != nil {
		return p, err
	}
	p.mounts = make([]resolvedMountPlan, 0, len(mountsRaw))
	for _, item := range mountsRaw {
		mountFields, e := r.object(item, 5, 3, 4)
		if e != nil {
			return p, e
		}
		var m resolvedMountPlan
		m.artifactDigest, e = r.string(mountFields, 1, 4096)
		if e != nil {
			return p, e
		}
		m.verifiedArtifactDigest, e = r.string(mountFields, 2, 4096)
		if e != nil {
			return p, e
		}
		m.payloadDigest, e = r.string(mountFields, 3, 4096)
		if e != nil {
			return p, e
		}
		m.targetPath, e = r.string(mountFields, 4, 4096)
		if e != nil {
			return p, e
		}
		m.readOnly, e = r.bool(mountFields, 5)
		if e != nil {
			return p, e
		}
		p.mounts = append(p.mounts, m)
	}
	p.networkAccess, err = r.bool(f, 10)
	if err != nil {
		return p, err
	}
	a, err := r.object(f[10].value, 14, 3, 3)
	if err != nil {
		return p, err
	}
	for _, field := range a {
		if !field.present {
			return p, errPrivateReplayUnavailable
		}
	}
	p.authority.runtimeProfileName, err = r.string(a, 1, 4096)
	if err != nil {
		return p, err
	}
	p.authority.codexCredential.applicable, err = r.bool(a, 2)
	if err != nil {
		return p, err
	}
	p.authority.codexCredential.cliPath, err = r.string(a, 3, 4096)
	if err != nil {
		return p, err
	}
	p.authority.codexCredential.credentialSource, err = r.string(a, 4, 4096)
	if err != nil {
		return p, err
	}
	p.authority.codexCredential.vaultSecretPath, err = r.string(a, 5, 4096)
	if err != nil {
		return p, err
	}
	p.authority.codexCredential.vaultSecretField, err = r.string(a, 6, 4096)
	if err != nil {
		return p, err
	}
	p.authority.workloadVault.mode, err = r.string(a, 7, 4096)
	if err != nil {
		return p, err
	}
	p.authority.workloadVault.address, err = r.string(a, 8, 4096)
	if err != nil {
		return p, err
	}
	p.authority.workloadVault.authMount, err = r.string(a, 9, 4096)
	if err != nil {
		return p, err
	}
	p.authority.workloadVault.authRole, err = r.string(a, 10, 4096)
	if err != nil {
		return p, err
	}
	p.authority.workloadVault.jwtAudience, err = r.string(a, 11, 4096)
	if err != nil {
		return p, err
	}
	p.authority.workloadZoneVaultConfigDigest, err = r.string(a, 12, 4096)
	if err != nil {
		return p, err
	}
	p.authority.trustMaterial.vaultCACert, err = r.bool(a, 13)
	if err != nil {
		return p, err
	}
	p.authority.trustMaterial.workloadTLSBundle, err = r.bool(a, 14)
	if err != nil {
		return p, err
	}
	p.runtimeSupportDigest, err = r.string(f, 12, 256)
	if err != nil {
		return p, err
	}
	p.runtimeIdentityTmpfsSize, err = func() (int64, error) { v, e := r.uint(f, 13, 8, 4294967295); return int64(v), e }()
	if err != nil {
		return p, err
	}
	j, err := r.object(f[13].value, 17, 3, 3)
	if err != nil {
		return p, err
	}
	for _, field := range j {
		if !field.present {
			return p, errPrivateReplayUnavailable
		}
	}
	job := resolvedJobEnvelope{}
	job.jobType, err = r.string(j, 1, 64)
	if err != nil {
		return p, err
	}
	job.groupName, err = r.string(j, 2, 64)
	if err != nil {
		return p, err
	}
	groupCount, err := r.uint(j, 3, 4, 2147483647)
	if err != nil || groupCount == 0 {
		return p, errPrivateReplayUnavailable
	}
	job.groupCount = int(groupCount)
	job.taskName, err = r.string(j, 4, 64)
	if err != nil {
		return p, err
	}
	job.driver, err = r.string(j, 5, 64)
	if err != nil {
		return p, err
	}
	job.user, err = r.string(j, 6, 64)
	if err != nil {
		return p, err
	}
	job.privileged, err = r.bool(j, 7)
	if err != nil {
		return p, err
	}
	job.securityOptions, err = r.strings(j[7].value, 32, 4096, 4)
	if err != nil {
		return p, err
	}
	readInt := func(id int) (int64, error) { v, e := r.uint(j, id, 8, 9223372036854775807); return int64(v), e }
	restartAttempts, err := r.uint(j, 9, 4, 2147483647)
	if err != nil {
		return p, err
	}
	job.restartPolicy.attempts = int(restartAttempts)
	job.restartPolicy.mode, err = r.string(j, 10, 64)
	if err != nil {
		return p, err
	}
	job.restartPolicy.interval, err = readInt(11)
	if err != nil {
		return p, err
	}
	job.restartPolicy.delay, err = readInt(12)
	if err != nil {
		return p, err
	}
	rescheduleAttempts, err := r.uint(j, 13, 4, 2147483647)
	if err != nil {
		return p, err
	}
	job.reschedulePolicy.attempts = int(rescheduleAttempts)
	job.reschedulePolicy.unlimited, err = r.bool(j, 14)
	if err != nil {
		return p, err
	}
	job.reschedulePolicy.delay, err = readInt(15)
	if err != nil {
		return p, err
	}
	job.reschedulePolicy.delayFunction, err = r.string(j, 16, 64)
	if err != nil {
		return p, err
	}
	job.reschedulePolicy.maxDelay, err = readInt(17)
	if err != nil {
		return p, err
	}
	p.jobEnvelope = job
	return p, nil
}

func (r *privateReplayReader) material(raw []byte) (resolvedMaterialFacts, error) {
	f, err := r.object(raw, 5, 2, 2)
	if err != nil {
		return resolvedMaterialFacts{}, err
	}
	for _, id := range []int{1, 2, 3} {
		if !f[id-1].present {
			return resolvedMaterialFacts{}, errPrivateReplayUnavailable
		}
	}
	var m resolvedMaterialFacts
	if len(f[0].value) > 262144 || len(f[1].value) > 262144 {
		return m, errPrivateReplayUnavailable
	}
	m.payloadBytes = bytes.Clone(f[0].value)
	m.runtimeSupportBytes = bytes.Clone(f[1].value)
	mounts, err := r.sequence(f[2].value, 8, 3)
	if err != nil {
		return m, err
	}
	m.mounts = make([]validatedMountArchive, 0, len(mounts))
	for _, item := range mounts {
		archive, e := r.object(item, 2, 3, 4)
		if e != nil {
			return m, e
		}
		if !archive[0].present || !archive[1].present || len(archive[0].value) > 262144 {
			return m, errPrivateReplayUnavailable
		}
		entriesRaw, e := r.sequence(archive[1].value, 256, 5)
		if e != nil {
			return m, e
		}
		resolvedArchive := validatedMountArchive{compressedBytes: bytes.Clone(archive[0].value), entries: make([]validatedMountEntry, 0, len(entriesRaw))}
		for _, entryRaw := range entriesRaw {
			entryFields, e := r.object(entryRaw, 4, 4, 6)
			if e != nil {
				return m, e
			}
			name, e := r.string(entryFields, 1, 4096)
			if e != nil {
				return m, e
			}
			directory, e := r.bool(entryFields, 2)
			if e != nil {
				return m, e
			}
			mode, e := r.uint(entryFields, 3, 4, 4294967295)
			if e != nil {
				return m, e
			}
			entry := validatedMountEntry{name: name, directory: directory, mode: os.FileMode(mode)}
			if directory {
				if entryFields[3].present {
					return m, errPrivateReplayUnavailable
				}
			} else {
				if !entryFields[3].present || len(entryFields[3].value) > 262144 {
					return m, errPrivateReplayUnavailable
				}
				entry.contents = make([]byte, len(entryFields[3].value))
				copy(entry.contents, entryFields[3].value)
			}
			resolvedArchive.entries = append(resolvedArchive.entries, entry)
		}
		m.mounts = append(m.mounts, resolvedArchive)
	}
	if f[3].present {
		if len(f[3].value) > 262144 {
			return m, errPrivateReplayUnavailable
		}
		m.trust.vaultCACertBytes = bytes.Clone(f[3].value)
	}
	if f[4].present {
		if len(f[4].value) > 262144 {
			return m, errPrivateReplayUnavailable
		}
		m.trust.workloadTLSBundleBytes = bytes.Clone(f[4].value)
	}
	return m, nil
}

func (r *privateReplayReader) placement(raw []byte) (hostMaterializationContext, resolvedCustodyPlacement, error) {
	f, err := r.object(raw, 6, 2, 2)
	if err != nil {
		return hostMaterializationContext{}, resolvedCustodyPlacement{}, err
	}
	for _, field := range f {
		if !field.present {
			return hostMaterializationContext{}, resolvedCustodyPlacement{}, errPrivateReplayUnavailable
		}
	}
	staging, err := r.string(f, 1, 4096)
	if err != nil {
		return hostMaterializationContext{}, resolvedCustodyPlacement{}, err
	}
	results, err := r.string(f, 2, 4096)
	if err != nil {
		return hostMaterializationContext{}, resolvedCustodyPlacement{}, err
	}
	spire, err := r.string(f, 3, 4096)
	if err != nil {
		return hostMaterializationContext{}, resolvedCustodyPlacement{}, err
	}
	datacenter, err := r.string(f, 4, 4096)
	if err != nil {
		return hostMaterializationContext{}, resolvedCustodyPlacement{}, err
	}
	uid, err := r.uint(f, 5, 4, 4294967295)
	if err != nil {
		return hostMaterializationContext{}, resolvedCustodyPlacement{}, err
	}
	gid, err := r.uint(f, 6, 4, 4294967295)
	if err != nil {
		return hostMaterializationContext{}, resolvedCustodyPlacement{}, err
	}
	owner := executionPlatformStateOwner{UID: int(uid), GID: int(gid)}
	host := newHostMaterializationContext(staging, results, owner, spire, datacenter)
	return host, resolvedCustodyPlacement{stagingRootDir: staging, resultsRootDir: results}, nil
}

func (r *privateReplayReader) image(raw []byte, plan resolvedExecutionPlan, host hostMaterializationContext) (privateSyntheticImagePlacement, error) {
	f, err := r.object(raw, 5, 2, 2)
	if err != nil {
		return privateSyntheticImagePlacement{}, err
	}
	for _, field := range f {
		if !field.present {
			return privateSyntheticImagePlacement{}, errPrivateReplayUnavailable
		}
	}
	ref, err := r.string(f, 1, 1024)
	if err != nil || ref != plan.runtimeProfile.image {
		return privateSyntheticImagePlacement{}, errPrivateReplayUnavailable
	}
	digest, err := r.required(f, 2)
	if err != nil || len(digest) != 32 {
		return privateSyntheticImagePlacement{}, errPrivateReplayUnavailable
	}
	issuer, err := r.string(f, 3, 1024)
	if err != nil || issuer == "" {
		return privateSyntheticImagePlacement{}, errPrivateReplayUnavailable
	}
	kind, err := r.uint(f, 4, 1, 1)
	if err != nil || kind != 1 {
		return privateSyntheticImagePlacement{}, errPrivateReplayUnavailable
	}
	topology, err := r.string(f, 5, 4096)
	if err != nil || topology != host.datacenter {
		return privateSyntheticImagePlacement{}, errPrivateReplayUnavailable
	}
	image, err := newPrivateSyntheticImagePlacement(digest, issuer)
	if err != nil {
		return privateSyntheticImagePlacement{}, errPrivateReplayUnavailable
	}
	return image, nil
}

func (r *privateReplayReader) identity(raw []byte) (reliableSubmitClaimRefs, error) {
	f, err := r.object(raw, 2, 2, 2)
	if err != nil {
		return reliableSubmitClaimRefs{}, err
	}
	callerRaw, err := r.required(f, 1)
	if err != nil || len(callerRaw) != 32 {
		return reliableSubmitClaimRefs{}, errPrivateReplayUnavailable
	}
	submitRaw, err := r.required(f, 2)
	if err != nil || len(submitRaw) != 32 {
		return reliableSubmitClaimRefs{}, errPrivateReplayUnavailable
	}
	caller, err := reliablesubmit.NewCallerRef(callerRaw)
	if err != nil {
		return reliableSubmitClaimRefs{}, errPrivateReplayUnavailable
	}
	submit, err := reliablesubmit.NewSubmitKeyRef(submitRaw)
	if err != nil {
		return reliableSubmitClaimRefs{}, errPrivateReplayUnavailable
	}
	claim, err := reliablesubmit.NewClaimID(caller, submit)
	if err != nil {
		return reliableSubmitClaimRefs{}, errPrivateReplayUnavailable
	}
	return reliableSubmitClaimRefs{callerRef: caller, submitKeyRef: submit, claimID: claim}, nil
}

func decodePrivateReplayOriginal(plaintext []byte, keys privateSyntheticKeyBundle, scope byte) (privateVerifiedOriginal, error) {
	r := privateReplayReader{}
	f, err := r.scopedPayload(plaintext, scope)
	if err != nil {
		return privateVerifiedOriginal{}, errPrivateReplayUnavailable
	}
	refs, err := r.identity(f[0].value)
	if err != nil {
		return privateVerifiedOriginal{}, errPrivateReplayUnavailable
	}
	intent, err := r.original(f[1].value)
	if err != nil {
		return privateVerifiedOriginal{}, errPrivateReplayUnavailable
	}
	planFacts, err := r.plan(f[2].value)
	if err != nil {
		return privateVerifiedOriginal{}, errPrivateReplayUnavailable
	}
	materialFacts, err := r.material(f[3].value)
	if err != nil {
		return privateVerifiedOriginal{}, errPrivateReplayUnavailable
	}
	host, placement, err := r.placement(f[6].value)
	if err != nil {
		return privateVerifiedOriginal{}, errPrivateReplayUnavailable
	}
	plan := newResolvedExecutionPlan(planFacts)
	material, err := newResolvedExecutionMaterial(&materialFacts)
	if err != nil {
		return privateVerifiedOriginal{}, errPrivateReplayUnavailable
	}
	resolved := resolvedExecution{plan: plan, material: material, host: host, custodyPlacement: placement}
	image, err := r.image(f[5].value, plan, host)
	if err != nil {
		return privateVerifiedOriginal{}, errPrivateReplayUnavailable
	}
	if plan.requestSchemaVersion != "v1" || plan.invocationSchemaVersion != "v1" ||
		plan.artifactDigest != intent.artifactDigest || plan.derivationSpecDigest != intent.derivationDigest ||
		plan.outputID != intent.outputID || plan.mode != ExecutionModeAsync {
		return privateVerifiedOriginal{}, errPrivateReplayUnavailable
	}
	if intent.timeout.present && plan.timeoutSeconds != int(intent.timeout.value) {
		return privateVerifiedOriginal{}, errPrivateReplayUnavailable
	}
	if intent.resources.present && (plan.resources.cpu != intent.resources.value.CPU || plan.resources.memoryMB != intent.resources.value.MemoryMB) {
		return privateVerifiedOriginal{}, errPrivateReplayUnavailable
	}
	if intent.profile.present && intent.profile.value != "" && plan.runtimeProfile.name != intent.profile.value {
		return privateVerifiedOriginal{}, errPrivateReplayUnavailable
	}
	if len(plan.runtimeCommand.arguments) < 12 || !slices.Equal(plan.runtimeCommand.arguments[12:], intent.argv.value) {
		return privateVerifiedOriginal{}, errPrivateReplayUnavailable
	}
	if len(intent.mounts.value) != len(plan.mounts) {
		return privateVerifiedOriginal{}, errPrivateReplayUnavailable
	}
	for i, mount := range intent.mounts.value {
		if !mount.readOnly.value || mount.artifactDigest != plan.mounts[i].artifactDigest || mount.targetPath != plan.mounts[i].targetPath {
			return privateVerifiedOriginal{}, errPrivateReplayUnavailable
		}
	}
	family, err := newReliableBindingFamily(intent.outerSchema, intent.contract)
	if err != nil {
		return privateVerifiedOriginal{}, errPrivateReplayUnavailable
	}
	assessment, err := buildReliableSubmitAdmissionBinding(resolved, family, keys.binding)
	if err != nil || assessment.effectReady {
		return privateVerifiedOriginal{}, errPrivateReplayUnavailable
	}
	delivery := privateReplayDelivery{originalIntent: intent, refs: refs, family: family}
	reencoded, err := encodePrivateReplayPayload(delivery, resolved, assessment, image, keys.bindingID, keys.envelopeID, scope)
	if err != nil || !hmac.Equal(reencoded, plaintext) {
		return privateVerifiedOriginal{}, errPrivateReplayUnavailable
	}
	encoder := privateReplayEncoder{}
	canonical := encoder.original(intent)
	if encoder.err != nil {
		return privateVerifiedOriginal{}, errPrivateReplayUnavailable
	}
	return privateVerifiedOriginal{claim: refs.claimID, intent: intent, intentCanonical: canonical, resolved: resolved, assessment: assessment}, nil
}

func verifyPrivateReplayOriginal(meta reliablesubmit.AuthenticatedClaimMeta, plaintext []byte, keys privateSyntheticKeyBundle) (privateVerifiedOriginal, error) {
	verified, err := decodePrivateReplayOriginal(plaintext, keys, 1)
	if err != nil || !meta.MatchesClaimAndPlan(verified.claim, verified.assessment.boundPlan) {
		return privateVerifiedOriginal{}, errPrivateReplayUnavailable
	}
	return verified, nil
}

type privateVerifiedOriginal struct {
	privateExecutionValue
	claim           reliablesubmit.ClaimID
	intent          privateReplayOriginalIntent
	intentCanonical []byte
	resolved        resolvedExecution
	assessment      admissionBindingAssessment
	ownAttempt      bool
}

func privateOriginalIntentEqual(a, b []byte) bool { return hmac.Equal(a, b) }
