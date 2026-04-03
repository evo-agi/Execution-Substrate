package signingv2

import (
	"encoding/json"
	"fmt"
	"sort"
)

func canonicalJSON(value any) ([]byte, error) {
	normalized, err := normalizeCanonicalValue(value)
	if err != nil {
		return nil, err
	}
	return marshalCanonicalValue(normalized)
}

func normalizeCanonicalValue(value any) (any, error) {
	switch typed := value.(type) {
	case map[string]any:
		normalized := make(map[string]any, len(typed))
		for key, entry := range typed {
			next, err := normalizeCanonicalValue(entry)
			if err != nil {
				return nil, err
			}
			normalized[key] = next
		}
		return normalized, nil
	case []any:
		normalized := make([]any, 0, len(typed))
		for _, entry := range typed {
			next, err := normalizeCanonicalValue(entry)
			if err != nil {
				return nil, err
			}
			normalized = append(normalized, next)
		}
		return normalized, nil
	case string, bool, nil:
		return typed, nil
	default:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return nil, err
		}
		var decoded any
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			return nil, err
		}
		return normalizeCanonicalValue(decoded)
	}
}

func marshalCanonicalValue(value any) ([]byte, error) {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		result := []byte{'{'}
		for index, key := range keys {
			if index > 0 {
				result = append(result, ',')
			}
			keyBytes, err := json.Marshal(key)
			if err != nil {
				return nil, err
			}
			result = append(result, keyBytes...)
			result = append(result, ':')
			valueBytes, err := marshalCanonicalValue(typed[key])
			if err != nil {
				return nil, err
			}
			result = append(result, valueBytes...)
		}
		result = append(result, '}')
		return result, nil
	case []any:
		result := []byte{'['}
		for index, entry := range typed {
			if index > 0 {
				result = append(result, ',')
			}
			entryBytes, err := marshalCanonicalValue(entry)
			if err != nil {
				return nil, err
			}
			result = append(result, entryBytes...)
		}
		result = append(result, ']')
		return result, nil
	case string, bool, nil:
		return json.Marshal(typed)
	default:
		return nil, fmt.Errorf("unsupported canonical value type %T", value)
	}
}
