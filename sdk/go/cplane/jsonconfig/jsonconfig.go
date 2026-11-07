// Package jsonconfig decodes a plugin's JSON configuration strictly.
//
// The host hands configuration bytes to the plugin unchanged, so the plugin
// is the only place a misspelled key or a wrong type can be caught. Decode
// therefore refuses anything it would otherwise have to guess about:
//
//   - the input must be exactly one JSON object;
//   - "schema_version" must be present and equal to the version the plugin
//     implements;
//   - every key must match a json field name of the target exactly, at every
//     nesting level (encoding/json alone would match case-insensitively);
//   - a key may appear only once per object (encoding/json alone would let
//     the later one win, merging nested objects);
//   - null is rejected anywhere, because encoding/json would otherwise give
//     the field its zero value silently.
//
// It uses only encoding/json and reflect, which work under standard Go and
// TinyGo. It lives outside the base cplane package, which avoids reflection.
package jsonconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// Version can be embedded in a configuration struct to declare the
// "schema_version" key that Decode requires.
type Version struct {
	SchemaVersion int `json:"schema_version"`
}

// Decode parses data into v, which must point to a struct that declares a
// "schema_version" field (embed Version for convenience). Errors name the
// offending key or value and begin with "configuration".
func Decode(data []byte, version int, v any) error {
	if err := checkKeys(data, reflect.TypeOf(v)); err != nil {
		return err
	}
	var header struct {
		SchemaVersion *int `json:"schema_version"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	if header.SchemaVersion == nil {
		return fmt.Errorf("configuration: schema_version is required")
	}
	if *header.SchemaVersion != version {
		return fmt.Errorf("configuration: schema_version must be %d (got %d)", version, *header.SchemaVersion)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	return nil
}

// frame is one open object or array in the token scan. typ is the struct
// type an object's keys must name, or an array's element type; nil leaves
// keys unchecked, as for a map or an interface value.
type frame struct {
	object  bool
	wantKey bool
	keys    map[string]bool
	typ     reflect.Type
	key     string       // the object key whose value comes next
	value   reflect.Type // type of the value after key
	path    string       // where this object or array sits, for messages
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// checkKeys accepts exactly one JSON object containing no null, no repeated
// key and no key that differs from target's json names.
func checkKeys(data []byte, target reflect.Type) error {
	tokens := json.NewDecoder(bytes.NewReader(data))
	first, err := tokens.Token()
	if err == io.EOF {
		return errors.New("configuration must be a JSON object (got no data)")
	}
	if err != nil || first != json.Delim('{') {
		return errors.New("configuration must be a JSON object")
	}
	stack := []frame{{object: true, wantKey: true, keys: map[string]bool{}, typ: structType(target)}}
	for len(stack) > 0 {
		token, err := tokens.Token()
		if err != nil {
			return fmt.Errorf("configuration: %w", err)
		}
		top := &stack[len(stack)-1]
		if top.object && top.wantKey {
			if token == json.Delim('}') {
				stack = valueDone(stack[:len(stack)-1])
				continue
			}
			key, _ := token.(string)
			path := join(top.path, key)
			if top.keys[key] {
				return fmt.Errorf("configuration: duplicate key %q", path)
			}
			top.keys[key] = true
			top.key, top.value = key, nil
			if top.typ != nil {
				field, ok := fieldType(top.typ, key)
				if !ok {
					return fmt.Errorf("configuration: unknown key %q", path)
				}
				top.value = field
			}
			top.wantKey = false
			continue
		}
		valueType, path := top.typ, top.path+"[]"
		if top.object {
			valueType, path = top.value, join(top.path, top.key)
		}
		switch token {
		case nil:
			return errors.New("configuration: null values are not supported")
		case json.Delim('{'):
			stack = append(stack, frame{object: true, wantKey: true, keys: map[string]bool{}, typ: structType(valueType), path: path})
		case json.Delim('['):
			stack = append(stack, frame{typ: elemType(valueType), path: path})
		case json.Delim(']'):
			stack = valueDone(stack[:len(stack)-1])
		default:
			stack = valueDone(stack)
		}
	}
	if _, err := tokens.Token(); err != io.EOF {
		return errors.New("configuration: expected one JSON object")
	}
	return nil
}

// valueDone records that the innermost object's pending value is complete.
func valueDone(stack []frame) []frame {
	if len(stack) > 0 && stack[len(stack)-1].object {
		stack[len(stack)-1].wantKey = true
	}
	return stack
}

func deref(t reflect.Type) reflect.Type {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}

func structType(t reflect.Type) reflect.Type {
	if t = deref(t); t != nil && t.Kind() == reflect.Struct {
		return t
	}
	return nil
}

func elemType(t reflect.Type) reflect.Type {
	if t = deref(t); t != nil && (t.Kind() == reflect.Slice || t.Kind() == reflect.Array) {
		return t.Elem()
	}
	return nil
}

// fieldType finds the field encoding/json would decode key into, requiring
// the json name to match exactly. Embedded structs contribute their fields.
func fieldType(t reflect.Type, key string) (reflect.Type, bool) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "-" && tag == "-" {
			continue
		}
		if f.Anonymous && name == "" {
			if embedded := structType(f.Type); embedded != nil {
				if field, ok := fieldType(embedded, key); ok {
					return field, true
				}
				continue
			}
		}
		if !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		if name == key {
			return f.Type, true
		}
	}
	return nil, false
}
