package main

import (
	"encoding/json"
	"os"
)

func readToken(path string) (token, error) {
	var t token
	raw, err := os.ReadFile(path)
	if err != nil {
		return t, err
	}
	return t, json.Unmarshal(raw, &t)
}

func mustCopy(from, to string) {
	raw, err := os.ReadFile(from)
	if err != nil {
		fail("copy", err)
	}
	if err := os.WriteFile(to, raw, 0o600); err != nil {
		fail("copy", err)
	}
}
