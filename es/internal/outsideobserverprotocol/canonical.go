// Package outsideobserverprotocol contains only inert, untrusted structural
// parsing for the proposed R6J-R9.28 outside-observer protocol. Parsing is not
// authentication, receipt consumption, process observation, or launch authority.
package outsideobserverprotocol

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"unicode/utf8"
)

const maxCanonicalBytes = 4_194_304
const maxCanonicalDepth = 128

// canonicalInteger preserves the exact lexical token until a selected field
// applies its own inclusive integer bounds. No float conversion occurs.
type canonicalInteger string

func canonicalMalformed() error { return fmt.Errorf("CANONICAL_JSON::MALFORMED") }

func parseCanonicalV2(raw []byte) (any, error) {
	if len(raw) == 0 || len(raw) > maxCanonicalBytes || !utf8.Valid(raw) {
		return nil, canonicalMalformed()
	}
	p := canonicalParser{raw: raw}
	v, err := p.value(0)
	if err != nil || p.pos != len(raw) {
		return nil, canonicalMalformed()
	}
	encoded, err := encodeCanonicalV2(v)
	if err != nil || !bytes.Equal(encoded, raw) {
		return nil, canonicalMalformed()
	}
	return v, nil
}

type canonicalParser struct {
	raw []byte
	pos int
}

func (p *canonicalParser) value(depth int) (any, error) {
	if depth > maxCanonicalDepth || p.pos >= len(p.raw) {
		return nil, canonicalMalformed()
	}
	switch p.raw[p.pos] {
	case '{':
		p.pos++
		obj := make(map[string]any)
		if p.take('}') {
			return obj, nil
		}
		var previous string
		first := true
		for {
			if p.pos >= len(p.raw) || p.raw[p.pos] != '"' {
				return nil, canonicalMalformed()
			}
			key, err := p.string()
			if err != nil || (!first && bytes.Compare([]byte(previous), []byte(key)) >= 0) {
				return nil, canonicalMalformed()
			}
			first = false
			previous = key
			if !p.take(':') {
				return nil, canonicalMalformed()
			}
			item, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			obj[key] = item
			if p.take('}') {
				return obj, nil
			}
			if !p.take(',') {
				return nil, canonicalMalformed()
			}
		}
	case '[':
		p.pos++
		arr := make([]any, 0)
		if p.take(']') {
			return arr, nil
		}
		for {
			item, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			arr = append(arr, item)
			if p.take(']') {
				return arr, nil
			}
			if !p.take(',') {
				return nil, canonicalMalformed()
			}
		}
	case '"':
		return p.string()
	case 't':
		if p.literal("true") {
			return true, nil
		}
	case 'f':
		if p.literal("false") {
			return false, nil
		}
	case 'n':
		if p.literal("null") {
			return nil, nil
		}
	default:
		if p.raw[p.pos] == '-' || isASCIIDigit(p.raw[p.pos]) {
			return p.integer()
		}
	}
	return nil, canonicalMalformed()
}

func (p *canonicalParser) take(ch byte) bool {
	if p.pos >= len(p.raw) || p.raw[p.pos] != ch {
		return false
	}
	p.pos++
	return true
}

func (p *canonicalParser) literal(s string) bool {
	if len(p.raw)-p.pos < len(s) || string(p.raw[p.pos:p.pos+len(s)]) != s {
		return false
	}
	p.pos += len(s)
	return true
}

func (p *canonicalParser) string() (string, error) {
	if !p.take('"') {
		return "", canonicalMalformed()
	}
	var out bytes.Buffer
	for p.pos < len(p.raw) {
		ch := p.raw[p.pos]
		p.pos++
		switch ch {
		case '"':
			return out.String(), nil
		case '\\':
			if p.pos >= len(p.raw) {
				return "", canonicalMalformed()
			}
			escaped := p.raw[p.pos]
			p.pos++
			switch escaped {
			case '"', '\\':
				out.WriteByte(escaped)
			case 'b':
				out.WriteByte('\b')
			case 't':
				out.WriteByte('\t')
			case 'n':
				out.WriteByte('\n')
			case 'f':
				out.WriteByte('\f')
			case 'r':
				out.WriteByte('\r')
			case 'u':
				if len(p.raw)-p.pos < 4 || p.raw[p.pos] != '0' || p.raw[p.pos+1] != '0' {
					return "", canonicalMalformed()
				}
				a, b := lowerHexNibble(p.raw[p.pos+2]), lowerHexNibble(p.raw[p.pos+3])
				if a < 0 || b < 0 {
					return "", canonicalMalformed()
				}
				value := byte(a*16 + b)
				if value > 0x1f || value == '\b' || value == '\t' || value == '\n' || value == '\f' || value == '\r' {
					return "", canonicalMalformed()
				}
				out.WriteByte(value)
				p.pos += 4
			default:
				return "", canonicalMalformed()
			}
		default:
			if ch < 0x20 {
				return "", canonicalMalformed()
			}
			out.WriteByte(ch)
		}
	}
	return "", canonicalMalformed()
}

func lowerHexNibble(b byte) int {
	if b >= '0' && b <= '9' {
		return int(b - '0')
	}
	if b >= 'a' && b <= 'f' {
		return int(b-'a') + 10
	}
	return -1
}

func isASCIIDigit(b byte) bool { return b >= '0' && b <= '9' }

func (p *canonicalParser) integer() (canonicalInteger, error) {
	start := p.pos
	negative := p.take('-')
	if p.pos >= len(p.raw) {
		return "", canonicalMalformed()
	}
	if p.raw[p.pos] == '0' {
		p.pos++
		if negative || (p.pos < len(p.raw) && isASCIIDigit(p.raw[p.pos])) {
			return "", canonicalMalformed()
		}
	} else {
		if p.raw[p.pos] < '1' || p.raw[p.pos] > '9' {
			return "", canonicalMalformed()
		}
		for p.pos < len(p.raw) && isASCIIDigit(p.raw[p.pos]) {
			p.pos++
		}
	}
	if p.pos < len(p.raw) {
		switch p.raw[p.pos] {
		case '.', 'e', 'E', '+':
			return "", canonicalMalformed()
		}
	}
	return canonicalInteger(string(p.raw[start:p.pos])), nil
}

func validIntegerToken(s string) bool {
	if s == "0" {
		return true
	}
	if s == "" || s == "-0" {
		return false
	}
	start := 0
	if s[0] == '-' {
		start = 1
	}
	if start >= len(s) || s[start] < '1' || s[start] > '9' {
		return false
	}
	for i := start + 1; i < len(s); i++ {
		if !isASCIIDigit(s[i]) {
			return false
		}
	}
	return true
}

func encodeCanonicalV2(v any) ([]byte, error) {
	var out bytes.Buffer
	if err := encodeCanonicalValue(&out, v, 0); err != nil || out.Len() > maxCanonicalBytes {
		return nil, canonicalMalformed()
	}
	return out.Bytes(), nil
}

func encodeCanonicalValue(out *bytes.Buffer, v any, depth int) error {
	if depth > maxCanonicalDepth || out.Len() > maxCanonicalBytes {
		return canonicalMalformed()
	}
	switch x := v.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		if x {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case canonicalInteger:
		if !validIntegerToken(string(x)) {
			return canonicalMalformed()
		}
		out.WriteString(string(x))
	case int:
		out.WriteString(strconv.FormatInt(int64(x), 10))
	case int64:
		out.WriteString(strconv.FormatInt(x, 10))
	case string:
		if err := encodeCanonicalString(out, x); err != nil {
			return err
		}
	case []any:
		out.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := encodeCanonicalValue(out, item, depth+1); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			if !utf8.ValidString(k) {
				return canonicalMalformed()
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := encodeCanonicalString(out, k); err != nil {
				return err
			}
			out.WriteByte(':')
			if err := encodeCanonicalValue(out, x[k], depth+1); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	default:
		return canonicalMalformed()
	}
	if out.Len() > maxCanonicalBytes {
		return canonicalMalformed()
	}
	return nil
}

func encodeCanonicalString(out *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return canonicalMalformed()
	}
	const digits = "0123456789abcdef"
	out.WriteByte('"')
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch ch {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\t':
			out.WriteString(`\t`)
		case '\n':
			out.WriteString(`\n`)
		case '\f':
			out.WriteString(`\f`)
		case '\r':
			out.WriteString(`\r`)
		default:
			if ch < 0x20 {
				out.WriteString(`\u00`)
				out.WriteByte(digits[ch>>4])
				out.WriteByte(digits[ch&15])
			} else {
				out.WriteByte(ch)
			}
		}
	}
	out.WriteByte('"')
	return nil
}
