package main

import (
	"bytes"
	"encoding/json"
)

func jsonMarshal(value any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func jsonObject(body []byte) (map[string]any, error) {
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	if doc == nil {
		return nil, ioUnexpected("empty health document")
	}
	return doc, nil
}

type ioUnexpected string

func (e ioUnexpected) Error() string { return string(e) }
