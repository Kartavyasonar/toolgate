package redact

import "strings"

// Redact recursively walks a data structure (map or slice) and replaces
// the values of any keys found in sensitiveKeys with "[REDACTED]".
// It returns the redacted data and the count of fields redacted.
func Redact(data any, sensitiveKeys []string) (any, int) {
	return walk(data, sensitiveKeys)
}

func walk(data any, keys []string) (any, int) {
	count := 0
	switch v := data.(type) {
	case map[string]any:
		for k, val := range v {
			if isSensitive(k, keys) {
				v[k] = "[REDACTED]"
				count++
			} else {
				newVal, c := walk(val, keys)
				v[k] = newVal
				count += c
			}
		}
		return v, count
	case []any:
		for i, item := range v {
			newItem, c := walk(item, keys)
			v[i] = newItem
			count += c
		}
		return v, count
	default:
		return data, 0
	}
}

func isSensitive(key string, keys []string) bool {
	lower := strings.ToLower(key)
	for _, k := range keys {
		if strings.ToLower(k) == lower {
			return true
		}
	}
	return false
}