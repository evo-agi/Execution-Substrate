package reliablesubmit

import (
	"bytes"
	"encoding/binary"
	"unicode/utf8"
)

// replayStructure validates every nested format-1 field before a checked
// reader can hand authenticated plaintext to admission. Admission alone owns
// source meaning, original intent and PB1 recomputation.
type replayStructure struct{ budget replayDecodeBudget }

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
	return v.budget.addLeaf(len(f.value))
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
	return visit(fields)
}

func (v *replayStructure) sequence(f replayField, max, depth int, optional bool, visit func([]byte) error) error {
	if f.state == 0 && optional {
		return nil
	}
	if f.state != 1 {
		return errReplayFormat
	}
	return parseReplaySequence(f.value, max, &v.budget, depth, visit)
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

func (v *replayStructure) provenance(f replayField) error {
	return v.object(f, 6, 2, false, func(a []replayField) error {
		for i := 0; i < 4; i++ {
			if err := v.scalar(a[i], 's', 256, false); err != nil {
				return err
			}
		}
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
	if len(fields) != 10 {
		return errReplayFormat
	}
	v := &replayStructure{budget: replayDecodeBudget{nodes: 10}}
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
		if err := v.scalar(image[3], '1', 1, false); err != nil || image[3].value[0] != 1 {
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
	if err := v.provenance(fields[7]); err != nil {
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
	if err := v.scalar(fields[9], '1', 1, false); err != nil || fields[9].value[0] != 1 {
		return errReplayFormat
	}
	return nil
}
