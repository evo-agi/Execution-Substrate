package reliablesubmit

import (
	"bytes"
	"context"
	"encoding/binary"
	"sync/atomic"
	"unicode/utf8"
)

// replayStructure validates every nested format-1 field before a checked
// reader can hand authenticated plaintext to admission. Admission alone owns
// source meaning, original intent and PB1 recomputation.
type replayStructure struct {
	budget  replayDecodeBudget
	element *progressOriginalNode
}

func (v *replayStructure) capture(f replayField) *progressOriginalNode {
	if f.progressNode != nil {
		return f.progressNode
	}
	if f.id == 0 {
		return v.element
	}
	return nil
}

func (v *replayStructure) scalar(f replayField, kind byte, max int, optional bool) error {
	if f.state == 0 && optional {
		return nil
	}
	if f.state != 1 || len(f.value) > max {
		return errReplayFormat
	}
	switch kind {
	case 's':
		if !utf8.Valid(f.value) {
			return errReplayFormat
		}
	case 'b':
		if len(f.value) != 1 || f.value[0] > 1 {
			return errReplayFormat
		}
	case '1':
		if len(f.value) != 1 {
			return errReplayFormat
		}
	case '2':
		if len(f.value) != 2 {
			return errReplayFormat
		}
	case '4':
		if len(f.value) != 4 {
			return errReplayFormat
		}
	case '8':
		if len(f.value) != 8 {
			return errReplayFormat
		}
	case 'd':
		if len(f.value) != 41 || f.value[0] > 2 {
			return errReplayFormat
		}
		if f.value[0] != 1 && (binary.BigEndian.Uint64(f.value[1:9]) != 0 || !bytes.Equal(f.value[9:], make([]byte, 32))) {
			return errReplayFormat
		}
	case 'x':
	default:
		return errReplayFormat
	}
	if err := v.budget.addLeaf(len(f.value)); err != nil {
		return err
	}
	if node := v.capture(f); node != nil {
		node.kind = kind
		switch kind {
		case 's':
			node.text = string(f.value)
		case 'x':
			node.blob = bytes.Clone(f.value)
		case 'd':
			node.number = binary.BigEndian.Uint64(f.value[1:9])
			node.descriptorState = f.value[0]
			copy(node.digest[:], f.value[9:])
		default:
			for _, b := range f.value {
				node.number = node.number<<8 | uint64(b)
			}
		}
	}
	return nil
}

func (v *replayStructure) object(f replayField, count, depth int, optional bool, visit func([]replayField) error) error {
	if f.state == 0 && optional {
		return nil
	}
	if f.state != 1 {
		return errReplayFormat
	}
	fields, err := parseReplayObject(f.value, count, &v.budget, depth, depth)
	if err != nil {
		return err
	}
	if node := v.capture(f); node != nil {
		node.kind = 'o'
		node.children = make([]progressOriginalNode, len(fields))
		for i := range fields {
			fields[i].progressNode = &node.children[i]
		}
	}
	return visit(fields)
}

func (v *replayStructure) sequence(f replayField, max, depth int, optional bool, visit func([]byte) error) error {
	if f.state == 0 && optional {
		return nil
	}
	if f.state != 1 {
		return errReplayFormat
	}
	node := v.capture(f)
	if node == nil {
		return parseReplaySequence(f.value, max, &v.budget, depth, visit)
	}
	node.kind = 'q'
	return parseReplaySequence(f.value, max, &v.budget, depth, func(raw []byte) error {
		node.children = append(node.children, progressOriginalNode{})
		previous := v.element
		v.element = &node.children[len(node.children)-1]
		err := visit(raw)
		v.element = previous
		return err
	})
}

func (v *replayStructure) stringSequence(f replayField, maxCount, maxLength, depth int, optional bool) error {
	return v.sequence(f, maxCount, depth, optional, func(raw []byte) error {
		return v.scalar(replayField{state: 1, value: raw}, 's', maxLength, false)
	})
}

func (v *replayStructure) stringMap(f replayField, maxCount int, optional bool) error {
	if f.state == 0 && optional {
		return nil
	}
	if f.state != 1 || len(f.value) < 2 {
		return errReplayFormat
	}
	count := int(binary.BigEndian.Uint16(f.value[:2]))
	if count > maxCount || v.budget.addElements(count) != nil {
		return errReplayFormat
	}
	node := v.capture(f)
	if node != nil {
		node.kind = 'm'
		node.entries = make([]progressOriginalEntry, 0, count)
	}
	offset := 2
	var previous []byte
	for i := 0; i < count; i++ {
		if len(f.value)-offset < 2 {
			return errReplayFormat
		}
		keyLength := int(binary.BigEndian.Uint16(f.value[offset : offset+2]))
		offset += 2
		if keyLength > 1024 || keyLength > len(f.value)-offset {
			return errReplayFormat
		}
		key := f.value[offset : offset+keyLength]
		offset += keyLength
		if !utf8.Valid(key) || i > 0 && bytes.Compare(previous, key) >= 0 || v.budget.addLeaf(len(key)) != nil {
			return errReplayFormat
		}
		previous = key
		if len(f.value)-offset < 4 {
			return errReplayFormat
		}
		valueLength := binary.BigEndian.Uint32(f.value[offset : offset+4])
		offset += 4
		if valueLength > 65536 || valueLength > uint32(len(f.value)-offset) {
			return errReplayFormat
		}
		value := f.value[offset : offset+int(valueLength)]
		offset += int(valueLength)
		if !utf8.Valid(value) || v.budget.addLeaf(len(value)) != nil {
			return errReplayFormat
		}
		if node != nil {
			node.entries = append(node.entries, progressOriginalEntry{key: string(key), value: string(value)})
		}
	}
	if offset != len(f.value) {
		return errReplayFormat
	}
	return nil
}

func (v *replayStructure) original(f replayField) error {
	return v.object(f, 15, 2, false, func(a []replayField) error {
		for _, id := range []int{1, 2} {
			if err := v.scalar(a[id-1], 's', 64, false); err != nil {
				return err
			}
		}
		if err := v.scalar(a[2], '1', 1, false); err != nil || a[2].value[0] != 1 {
			return errReplayFormat
		}
		if err := v.scalar(a[3], 's', 64, true); err != nil {
			return err
		}
		for _, id := range []int{5, 6, 7} {
			if err := v.scalar(a[id-1], 's', 256, false); err != nil {
				return err
			}
		}
		if err := v.scalar(a[7], 's', 32, true); err != nil {
			return err
		}
		if err := v.scalar(a[8], '4', 4, true); err != nil {
			return err
		}
		if err := v.object(a[9], 2, 3, true, func(r []replayField) error {
			for _, f := range r {
				if err := v.scalar(f, '4', 4, false); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return err
		}
		if err := v.stringSequence(a[10], 100, 65536, 3, true); err != nil {
			return err
		}
		if err := v.stringMap(a[11], 128, true); err != nil {
			return err
		}
		if err := v.sequence(a[12], 8, 3, true, func(raw []byte) error {
			return v.object(replayField{state: 1, value: raw}, 3, 4, false, func(m []replayField) error {
				if err := v.object(m[0], 1, 5, false, func(source []replayField) error { return v.scalar(source[0], 's', 256, false) }); err != nil {
					return err
				}
				if err := v.scalar(m[1], 's', 4096, false); err != nil {
					return err
				}
				return v.scalar(m[2], 'b', 1, true)
			})
		}); err != nil {
			return err
		}
		if err := v.stringMap(a[13], 128, true); err != nil {
			return err
		}
		return v.scalar(a[14], 's', 65536, true)
	})
}

func (v *replayStructure) plan(f replayField) error {
	return v.object(f, 14, 2, false, func(a []replayField) error {
		for group := 0; group < 7; group++ {
			g := group
			if err := v.object(a[group], 2, 3, false, func(pair []replayField) error {
				switch g {
				case 0:
					if err := v.scalar(pair[0], 's', 64, false); err != nil {
						return err
					}
					return v.scalar(pair[1], 's', 64, false)
				case 1:
					if err := v.scalar(pair[0], 's', 32, false); err != nil {
						return err
					}
					return v.scalar(pair[1], '4', 4, false)
				case 2:
					if err := v.scalar(pair[0], '4', 4, false); err != nil {
						return err
					}
					return v.scalar(pair[1], '4', 4, false)
				case 3:
					if err := v.scalar(pair[0], 's', 1024, false); err != nil {
						return err
					}
					return v.scalar(pair[1], 's', 1024, false)
				case 4, 5:
					if err := v.scalar(pair[0], 's', 256, false); err != nil {
						return err
					}
					return v.scalar(pair[1], 's', 256, false)
				default:
					if err := v.scalar(pair[0], 's', 4096, false); err != nil {
						return err
					}
					return v.stringSequence(pair[1], 112, 65536, 4, false)
				}
			}); err != nil {
				return err
			}
		}
		if err := v.stringMap(a[7], 160, false); err != nil {
			return err
		}
		if err := v.sequence(a[8], 8, 3, false, func(raw []byte) error {
			return v.object(replayField{state: 1, value: raw}, 5, 4, false, func(m []replayField) error {
				for i := 0; i < 4; i++ {
					if err := v.scalar(m[i], 's', 4096, false); err != nil {
						return err
					}
				}
				return v.scalar(m[4], 'b', 1, false)
			})
		}); err != nil {
			return err
		}
		if err := v.scalar(a[9], 'b', 1, false); err != nil {
			return err
		}
		if err := v.object(a[10], 14, 3, false, func(auth []replayField) error {
			for i, f := range auth {
				kind := byte('s')
				max := 4096
				if i == 1 || i == 12 || i == 13 {
					kind = 'b'
					max = 1
				}
				if err := v.scalar(f, kind, max, false); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return err
		}
		if err := v.scalar(a[11], 's', 256, false); err != nil {
			return err
		}
		if err := v.scalar(a[12], '8', 8, false); err != nil {
			return err
		}
		return v.object(a[13], 17, 3, false, func(job []replayField) error {
			for i, f := range job {
				kind := byte('s')
				max := 64
				switch i {
				case 2, 8, 12:
					kind = '4'
					max = 4
				case 6, 13:
					kind = 'b'
					max = 1
				case 10, 11, 14, 16:
					kind = '8'
					max = 8
				case 7:
					if err := v.stringSequence(f, 32, 4096, 4, false); err != nil {
						return err
					}
					continue
				}
				if err := v.scalar(f, kind, max, false); err != nil {
					return err
				}
			}
			return nil
		})
	})
}

func (v *replayStructure) material(f replayField) error {
	return v.object(f, 5, 2, false, func(a []replayField) error {
		for i := 0; i < 2; i++ {
			if err := v.scalar(a[i], 'x', 262144, false); err != nil {
				return err
			}
		}
		if err := v.sequence(a[2], 8, 3, false, func(raw []byte) error {
			return v.object(replayField{state: 1, value: raw}, 2, 4, false, func(m []replayField) error {
				if err := v.scalar(m[0], 'x', 262144, false); err != nil {
					return err
				}
				return v.sequence(m[1], 256, 5, false, func(entryRaw []byte) error {
					return v.object(replayField{state: 1, value: entryRaw}, 4, 5, false, func(entry []replayField) error {
						if err := v.scalar(entry[0], 's', 4096, false); err != nil {
							return err
						}
						if err := v.scalar(entry[1], 'b', 1, false); err != nil {
							return err
						}
						if err := v.scalar(entry[2], '4', 4, false); err != nil {
							return err
						}
						return v.scalar(entry[3], 'x', 262144, true)
					})
				})
			})
		}); err != nil {
			return err
		}
		for i := 3; i < 5; i++ {
			if err := v.scalar(a[i], 'x', 262144, true); err != nil {
				return err
			}
		}
		return nil
	})
}

func (v *replayStructure) assessment(f replayField) error {
	return v.object(f, 4, 2, false, func(a []replayField) error {
		if err := v.scalar(a[0], 'x', 258, false); err != nil {
			return err
		}
		for i := 1; i < 3; i++ {
			if err := v.scalar(a[i], '2', 2, false); err != nil {
				return err
			}
		}
		return v.object(a[3], 5, 3, false, func(m []replayField) error {
			for _, i := range []int{0, 1, 3, 4} {
				if err := v.scalar(m[i], 'd', 41, false); err != nil {
					return err
				}
			}
			return v.sequence(m[2], 8, 4, false, func(raw []byte) error {
				return v.object(replayField{state: 1, value: raw}, 5, 5, false, func(mount []replayField) error {
					for i := 0; i < 3; i++ {
						if err := v.scalar(mount[i], 's', 256, false); err != nil {
							return err
						}
					}
					if err := v.scalar(mount[3], 'd', 41, false); err != nil {
						return err
					}
					return v.sequence(mount[4], 256, 6, false, func(raw []byte) error {
						return v.object(replayField{state: 1, value: raw}, 4, 5, false, func(entry []replayField) error {
							if err := v.scalar(entry[0], 's', 4096, false); err != nil {
								return err
							}
							if err := v.scalar(entry[1], 'b', 1, false); err != nil {
								return err
							}
							if err := v.scalar(entry[2], '4', 4, false); err != nil {
								return err
							}
							return v.scalar(entry[3], 'd', 41, false)
						})
					})
				})
			})
		})
	})
}

// OperationalEvidenceLimit bounds the retained signed evidence record of a
// scope-3 original. Custody and admission share this one value.
const OperationalEvidenceLimit = 256 * 1024

func (v *replayStructure) provenance(f replayField, scope byte) error {
	return v.object(f, 6, 2, false, func(a []replayField) error {
		variant := string(a[0].value)
		// Scope 3 has exactly one provenance literal. Any other value,
		// including the literal PR #12 first published, is refused here.
		if scope == 2 && variant != "synthetic_progress_nonoperational_v1" ||
			scope == 3 && variant != "operational_local_v2" {
			return errReplayFormat
		}
		for i := 0; i < 4; i++ {
			if err := v.scalar(a[i], 's', 256, false); err != nil {
				return err
			}
		}
		if scope == 3 {
			if len(a[4].value) == 0 || !utf8.Valid(a[4].value) ||
				v.scalar(a[4], 'x', OperationalEvidenceLimit, false) != nil {
				return errReplayFormat
			}
		} else {
			if err := v.sequence(a[4], 8, 3, false, func(raw []byte) error {
				return v.object(replayField{state: 1, value: raw}, 3, 4, false, func(m []replayField) error {
					for _, f := range m {
						if err := v.scalar(f, 's', 256, false); err != nil {
							return err
						}
					}
					return nil
				})
			}); err != nil {
				return err
			}
		}
		return v.object(a[5], 2, 3, false, func(flags []replayField) error {
			for _, f := range flags {
				if err := v.scalar(f, 'b', 1, false); err != nil {
					return err
				}
			}
			return nil
		})
	})
}

func validateReplayPayloadStructure(fields []replayField) error {
	return validateReplayPayloadStructureForScope(fields, 1)
}

func validateReplayPayloadStructureForScope(fields []replayField, scope byte) error {
	format, known := replayFormatForScope(int64(scope))
	if !known || len(fields) != format.fieldCount() {
		return errReplayFormat
	}
	v := &replayStructure{budget: replayDecodeBudget{nodes: len(fields)}}
	if err := v.object(fields[0], 2, 2, false, func(identity []replayField) error {
		for _, f := range identity {
			if err := v.scalar(f, 'x', 32, false); err != nil || len(f.value) != 32 {
				return errReplayFormat
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if err := v.original(fields[1]); err != nil {
		return err
	}
	if err := v.plan(fields[2]); err != nil {
		return err
	}
	if err := v.material(fields[3]); err != nil {
		return err
	}
	if err := v.assessment(fields[4]); err != nil {
		return err
	}
	if err := v.object(fields[5], 5, 2, false, func(image []replayField) error {
		for _, i := range []int{0, 2} {
			if err := v.scalar(image[i], 's', 1024, false); err != nil {
				return err
			}
		}
		if err := v.scalar(image[1], 'x', 32, false); err != nil || len(image[1].value) != 32 {
			return errReplayFormat
		}
		kind := byte(1)
		if scope == 3 {
			kind = 2
		}
		if err := v.scalar(image[3], '1', 1, false); err != nil || image[3].value[0] != kind {
			return errReplayFormat
		}
		return v.scalar(image[4], 's', 4096, false)
	}); err != nil {
		return err
	}
	if err := v.object(fields[6], 6, 2, false, func(placement []replayField) error {
		for i := 0; i < 4; i++ {
			if err := v.scalar(placement[i], 's', 4096, false); err != nil {
				return err
			}
		}
		for i := 4; i < 6; i++ {
			if err := v.scalar(placement[i], '4', 4, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if err := v.provenance(fields[7], scope); err != nil {
		return err
	}
	if err := v.object(fields[8], 6, 2, false, func(keys []replayField) error {
		for _, i := range []int{0, 3, 4, 5} {
			if err := v.scalar(keys[i], '2', 2, false); err != nil {
				return err
			}
		}
		for _, i := range []int{1, 2} {
			if err := v.scalar(keys[i], 's', 64, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if err := v.scalar(fields[9], '1', 1, false); err != nil || fields[9].value[0] != scope {
		return errReplayFormat
	}
	if scope == 3 {
		return v.operationalDeployment(fields)
	}
	return nil
}

// A progress view is a projection of typed fields from a structurally checked
// original. Neither the entire plaintext nor a serialized subtree crosses
// this boundary. Admission consumes the typed data and owns PB1 semantics.
type progressOriginalNode struct {
	kind            byte
	text            string
	blob            []byte
	number          uint64
	descriptorState byte
	digest          [32]byte
	children        []progressOriginalNode
	entries         []progressOriginalEntry
}

type progressOriginalEntry struct{ key, value string }

type progressOriginalLifetime struct {
	ctx    context.Context
	closed atomic.Bool
}

func (l *progressOriginalLifetime) live() bool {
	return l != nil && !l.closed.Load() && l.ctx.Err() == nil
}

type ProgressOriginalView struct {
	privateReplayRedacted
	life  *progressOriginalLifetime
	nodes [10]progressOriginalNode
}

type ProgressOriginalField struct {
	privateReplayRedacted
	life *progressOriginalLifetime
	node *progressOriginalNode
}

func progressView(ctx context.Context, plaintext []byte) (*ProgressOriginalView, error) {
	fields, err := progressReplayFormat.parsePayload(plaintext)
	if err != nil {
		return nil, err
	}
	view := &ProgressOriginalView{life: &progressOriginalLifetime{ctx: ctx}}
	for i := range fields {
		fields[i].progressNode = &view.nodes[i]
	}
	if err := validateReplayPayloadStructureForScope(fields, 2); err != nil {
		return nil, err
	}
	return view, nil
}

func (v *ProgressOriginalView) Fields() ([]ProgressOriginalField, error) {
	if v == nil || !v.life.live() {
		return nil, errClaimStoreUnavailable
	}
	return progressFields(v.life, v.nodes[:]), nil
}

func progressFields(life *progressOriginalLifetime, nodes []progressOriginalNode) []ProgressOriginalField {
	fields := make([]ProgressOriginalField, len(nodes))
	for i := range fields {
		fields[i] = ProgressOriginalField{life: life, node: &nodes[i]}
	}
	return fields
}

func (f ProgressOriginalField) Kind() (byte, error) {
	if !f.life.live() || f.node == nil {
		return 0, errClaimStoreUnavailable
	}
	return f.node.kind, nil
}

func (f ProgressOriginalField) Children() []ProgressOriginalField {
	if !f.life.live() || f.node == nil || (f.node.kind != 'o' && f.node.kind != 'q') {
		return nil
	}
	return progressFields(f.life, f.node.children)
}

func (f ProgressOriginalField) Strings() map[string]string {
	if !f.life.live() || f.node == nil || f.node.kind != 'm' {
		return nil
	}
	result := make(map[string]string, len(f.node.entries))
	for _, entry := range f.node.entries {
		result[entry.key] = entry.value
	}
	return result
}

func (f ProgressOriginalField) Text() string {
	if !f.life.live() || f.node == nil || f.node.kind != 's' {
		return ""
	}
	return f.node.text
}

func (f ProgressOriginalField) Number() uint64 {
	if !f.life.live() || f.node == nil {
		return 0
	}
	switch f.node.kind {
	case '1', '2', '4', '8', 'b':
		return f.node.number
	default:
		return 0
	}
}

func (f ProgressOriginalField) Bytes() []byte {
	if !f.life.live() || f.node == nil || f.node.kind != 'x' {
		return nil
	}
	return bytes.Clone(f.node.blob)
}

func (f ProgressOriginalField) MaterialDescriptor() (byte, uint64, [32]byte) {
	if !f.life.live() || f.node == nil || f.node.kind != 'd' {
		return 0, 0, [32]byte{}
	}
	return f.node.descriptorState, f.node.number, f.node.digest
}
