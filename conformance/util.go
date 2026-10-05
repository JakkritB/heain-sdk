package conformance

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
)

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

// hostOwner is the host user the shared directory belongs to; files the
// tool containers (root) write there are handed to it.
func hostOwner() (int, int) {
	u, _ := strconv.Atoi(os.Getenv("HOST_UID"))
	g, _ := strconv.Atoi(os.Getenv("HOST_GID"))
	return u, g
}

// writeShared writes a file in the shared directory and gives it to the
// host user.
func writeShared(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	chownHost(tmp)
	return os.Rename(tmp, path)
}

func writeJSONFile(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeShared(path, b, 0o644)
}

func chownHost(path string) {
	if u, g := hostOwner(); u > 0 {
		_ = os.Chown(path, u, g)
		_ = os.Chown(filepath.Dir(path), u, g)
	}
}

func bytesContains(b, sub []byte) bool { return bytes.Contains(b, sub) }
