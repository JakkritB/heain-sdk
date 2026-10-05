// Package conformance is the heain conformance suite (spec 05): a host
// command that builds and starts heain-core and the app under test in
// Docker Compose, and a test driver that runs groups C1-C14 against them.
// Every image is built FROM scratch from static binaries, so nothing is
// pulled from a registry.
package conformance

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Conf is conformance.yaml, shipped by the app next to its manifest
// (author decision 2026-10-05): the inputs the suite cannot invent.
type Conf struct {
	Manifest string   `yaml:"manifest" json:"manifest"`
	Prebuild []string `yaml:"prebuild,omitempty" json:"prebuild,omitempty"`
	Port     int      `yaml:"port,omitempty" json:"port,omitempty"`
	// Endpoints: one sample request per endpoint the suite should call.
	Endpoints []Call `yaml:"endpoints,omitempty" json:"endpoints,omitempty"`
	// Jobs: one sample job per execution: job capability.
	Jobs []JobCase `yaml:"jobs,omitempty" json:"jobs,omitempty"`
	P5   *P5Case   `yaml:"p5,omitempty" json:"p5,omitempty"`
	P7   *P7Case   `yaml:"p7,omitempty" json:"p7,omitempty"`
}

// Call is one request to the app under test.
type Call struct {
	Method string         `yaml:"method" json:"method"`
	Path   string         `yaml:"path" json:"path"`
	Body   map[string]any `yaml:"body,omitempty" json:"body,omitempty"`
	Expect int            `yaml:"expect,omitempty" json:"expect,omitempty"`
	// Secret is a string of the input that must never appear in core's
	// audit, records, volumes or network traffic.
	Secret string `yaml:"secret,omitempty" json:"secret,omitempty"`
}

// JobCase is one sample job.
type JobCase struct {
	Capability   string `yaml:"capability" json:"capability"`
	Payload      string `yaml:"payload" json:"payload"`
	ExpectOutput string `yaml:"expect_output,omitempty" json:"expect_output,omitempty"`
	Delivery     string `yaml:"delivery,omitempty" json:"delivery,omitempty"` // STAGED (default) | IMMEDIATE
}

// P5Case triggers a P5 proposal in the app.
type P5Case struct {
	Propose Call   `yaml:"propose" json:"propose"`
	Status  *Call  `yaml:"status,omitempty" json:"status,omitempty"` // path may contain {action_id}
	Type    string `yaml:"type" json:"type"`                         // the action type the app proposes
}

// P7Case triggers a P7 broadcast in the app.
type P7Case struct {
	Broadcast Call     `yaml:"broadcast" json:"broadcast"`
	Sensitive []string `yaml:"sensitive,omitempty" json:"sensitive,omitempty"` // fields that must be removed
}

// LoadConf reads <dir>/conformance.yaml.
func LoadConf(dir string) (Conf, error) {
	var c Conf
	raw, err := os.ReadFile(filepath.Join(dir, "conformance.yaml"))
	if err != nil {
		return c, err
	}
	dec := yaml.NewDecoder(bytesReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("conformance.yaml: %w", err)
	}
	if c.Manifest == "" {
		c.Manifest = "heain-app.yaml"
	}
	if c.Port == 0 {
		c.Port = 19443
	}
	return c, nil
}
