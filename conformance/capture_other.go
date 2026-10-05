//go:build !linux

package conformance

import "errors"

// Capture needs Linux (AF_PACKET).
func Capture(iface, markersFile, out string) error { return errors.New("capture needs linux") }
