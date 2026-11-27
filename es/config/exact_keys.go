package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// refuseAmbiguousKeys refuses an ES configuration document that
// encoding/json reads differently from a reader that matches keys exactly
// and lets the last of two equal keys win: Python's json module, jq, the
// readiness line of scripts/internal/bringup.sh, or a person. encoding/json
// matches a key to a field without regard to letter case (Unicode simple
// folding, so "ſ" reads as "s" and the Kelvin sign as "k"), and it merges a
// repeated key into what the first one set, field by field for objects and
// element by element for arrays. So the document must name every field
// exactly as ES spells it, and no object may hold the same key twice.
// Load calls it with the value the document decoded into, so the shapes
// agree. It reads the value's type only, never a reflect.Value, so it can
// neither read nor write what the value holds.
func refuseAmbiguousKeys(document []byte, decoded any) error {
	return checkExactKeys(document, reflect.TypeOf(decoded), "")
}

var jsonUnmarshalerType = reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()

func checkExactKeys(raw json.RawMessage, t reflect.Type, path string) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || reflect.PointerTo(t).Implements(jsonUnmarshalerType) {
		return nil
	}
	switch t.Kind() {
	case reflect.Struct:
		keys, values, err := jsonObjectMembers(raw, path)
		if err != nil {
			return err
		}
		fields := jsonFieldTypes(t)
		for i, key := range keys {
			field, ok := fields[key]
			if !ok {
				for name := range fields {
					if strings.EqualFold(name, key) {
						return fmt.Errorf("%s: the key %q must be spelled exactly %q", jsonPathOrTop(path), key, name)
					}
				}
				return fmt.Errorf("%s: unknown key %q", jsonPathOrTop(path), key)
			}
			if err := checkExactKeys(values[i], field, jsonPathJoin(path, key)); err != nil {
				return err
			}
		}
	case reflect.Map:
		keys, values, err := jsonObjectMembers(raw, path)
		if err != nil {
			return err
		}
		for i, key := range keys {
			if err := checkExactKeys(values[i], t.Elem(), jsonPathJoin(path, key)); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		if t.Elem().Kind() == reflect.Uint8 && t.Kind() == reflect.Slice {
			return nil
		}
		var elements []json.RawMessage
		if err := json.Unmarshal(raw, &elements); err != nil {
			return fmt.Errorf("%s: %w", jsonPathOrTop(path), err)
		}
		for i, element := range elements {
			if err := checkExactKeys(element, t.Elem(), fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

// jsonObjectMembers returns the keys of one JSON object in order with their
// raw values, and refuses a key that appears twice.
func jsonObjectMembers(raw json.RawMessage, path string) ([]string, []json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil, nil, fmt.Errorf("%s: not a JSON object", jsonPathOrTop(path))
	}
	var keys []string
	var values []json.RawMessage
	seen := map[string]struct{}{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", jsonPathOrTop(path), err)
		}
		key, ok := token.(string)
		if !ok {
			return nil, nil, fmt.Errorf("%s: not a JSON object", jsonPathOrTop(path))
		}
		if _, repeated := seen[key]; repeated {
			return nil, nil, fmt.Errorf("%s: the key %q appears more than once", jsonPathOrTop(path), key)
		}
		seen[key] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", jsonPathOrTop(path), err)
		}
		keys = append(keys, key)
		values = append(values, value)
	}
	return keys, values, nil
}

// jsonFieldTypes maps each JSON key of a struct to its field's type, the
// way encoding/json names fields: the name in the json tag, or the Go
// field name; promoted fields of untagged embedded structs; no "-" fields
// and no unexported ones.
func jsonFieldTypes(t reflect.Type) map[string]reflect.Type {
	fields := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name == "-" && field.Tag.Get("json") == "-" {
			continue
		}
		if field.Anonymous && name == "" {
			embedded := field.Type
			for embedded.Kind() == reflect.Pointer {
				embedded = embedded.Elem()
			}
			if embedded.Kind() == reflect.Struct {
				for key, value := range jsonFieldTypes(embedded) {
					if _, ok := fields[key]; !ok {
						fields[key] = value
					}
				}
				continue
			}
		}
		if !field.IsExported() {
			continue
		}
		if name == "" {
			name = field.Name
		}
		fields[name] = field.Type
	}
	return fields
}

func jsonPathJoin(path string, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func jsonPathOrTop(path string) string {
	if path == "" {
		return "the top level"
	}
	return path
}
