// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
)

func digestCanonical(value interface{}) (string, error) {
	data, err := canonicalJSON(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func canonicalJSON(value interface{}) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonicalJSON(&buf, value); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonicalJSON(buf *bytes.Buffer, value interface{}) error {
	switch v := value.(type) {
	case nil:
		buf.WriteString("null")
	case string:
		return writeJSONString(buf, v)
	case bool:
		if v {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case int:
		buf.WriteString(fmt.Sprintf("%d", v))
	case int64:
		buf.WriteString(fmt.Sprintf("%d", v))
	case int32:
		buf.WriteString(fmt.Sprintf("%d", v))
	case uint:
		buf.WriteString(fmt.Sprintf("%d", v))
	case uint64:
		buf.WriteString(fmt.Sprintf("%d", v))
	case uint32:
		buf.WriteString(fmt.Sprintf("%d", v))
	case float64:
		return writeCanonicalFloat(buf, v)
	case float32:
		return writeCanonicalFloat(buf, float64(v))
	case json.Number:
		f, err := v.Float64()
		if err != nil {
			return fmt.Errorf("invalid JSON number %q", v)
		}
		return writeCanonicalFloat(buf, f)
	case []interface{}:
		buf.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalJSON(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case []string:
		items := make([]interface{}, len(v))
		for i, item := range v {
			items[i] = item
		}
		return writeCanonicalJSON(buf, items)
	case map[string]interface{}:
		return writeCanonicalMap(buf, v)
	case map[string]string:
		m := make(map[string]interface{}, len(v))
		for key, item := range v {
			m[key] = item
		}
		return writeCanonicalMap(buf, m)
	default:
		normalized, err := normalizeJSONValue(value)
		if err != nil {
			return fmt.Errorf("unsupported canonical JSON type %T", value)
		}
		return writeCanonicalJSON(buf, normalized)
	}
	return nil
}

func writeCanonicalFloat(buf *bytes.Buffer, value float64) error {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return fmt.Errorf("non-finite number %v cannot be canonicalized", value)
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	buf.Write(data)
	return nil
}

func writeCanonicalMap(buf *bytes.Buffer, value map[string]interface{}) error {
	keys := make([]string, 0, len(value))
	for key := range value {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return utf16Less(keys[i], keys[j])
	})

	buf.WriteByte('{')
	for i, key := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := writeJSONString(buf, key); err != nil {
			return err
		}
		buf.WriteByte(':')
		if err := writeCanonicalJSON(buf, value[key]); err != nil {
			return err
		}
	}
	buf.WriteByte('}')
	return nil
}

func writeJSONString(buf *bytes.Buffer, value string) error {
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return err
	}
	buf.WriteString(strings.TrimSuffix(encoded.String(), "\n"))
	return nil
}

func utf16Less(left, right string) bool {
	leftUnits := utf16.Encode([]rune(left))
	rightUnits := utf16.Encode([]rune(right))
	limit := len(leftUnits)
	if len(rightUnits) < limit {
		limit = len(rightUnits)
	}
	for i := 0; i < limit; i++ {
		if leftUnits[i] == rightUnits[i] {
			continue
		}
		return leftUnits[i] < rightUnits[i]
	}
	return len(leftUnits) < len(rightUnits)
}

func normalizeJSONValue(value interface{}) (interface{}, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var normalized interface{}
	if err := json.Unmarshal(data, &normalized); err != nil {
		return nil, err
	}
	return normalized, nil
}

func newApprovalID(prefix string) string {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", prefix, time.Now().UnixNano())))
		return prefix + "_" + hex.EncodeToString(sum[:8])
	}
	return prefix + "_" + hex.EncodeToString(random[:])
}
