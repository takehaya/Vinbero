// Package jsonconfig decodes a plugin's JSON configuration strictly.
//
// The host hands configuration bytes to the plugin unchanged, so the plugin
// is the only place a misspelled key or a wrong type can be caught. Decode
// therefore refuses anything it would otherwise have to guess about:
//
//   - the input must be exactly one JSON object;
//   - "schema_version" must be present and equal to the version the plugin
//     implements;
//   - keys the target struct does not declare are rejected;
//   - null is rejected anywhere, because encoding/json would otherwise give
//     the field its zero value silently.
//
// It uses only encoding/json, which works under standard Go and TinyGo.
// It lives outside the base cplane package, which avoids reflection.
package jsonconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	if err := checkShape(data); err != nil {
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

// checkShape accepts exactly one JSON object containing no null.
func checkShape(data []byte) error {
	tokens := json.NewDecoder(bytes.NewReader(data))
	first, err := tokens.Token()
	if err == io.EOF {
		return errors.New("configuration must be a JSON object (got no data)")
	}
	if err != nil || first != json.Delim('{') {
		return errors.New("configuration must be a JSON object")
	}
	for depth := 1; depth > 0; {
		token, err := tokens.Token()
		if err != nil {
			return fmt.Errorf("configuration: %w", err)
		}
		switch token {
		case nil:
			return errors.New("configuration: null values are not supported")
		case json.Delim('{'), json.Delim('['):
			depth++
		case json.Delim('}'), json.Delim(']'):
			depth--
		}
	}
	if _, err := tokens.Token(); err != io.EOF {
		return errors.New("configuration: expected one JSON object")
	}
	return nil
}
