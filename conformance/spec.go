// Package conformance is the heain conformance suite (spec 05): one
// command builds heain-core, starts its nodes as processes on this machine,
// starts the app under test with the app's own command -- any language, any
// packaging (author decision 2026-10-06: Docker is not required) -- and
// runs groups C1-C14 against them.
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
	Manifest string `yaml:"manifest" json:"manifest"`
	// Build runs once in the app directory before the tests (optional).
	Build []string `yaml:"build,omitempty" json:"build,omitempty"`
	// Start runs the app in the foreground, in the app directory, with the
	// HEAIN_* variables of the container contract set (heain.StartFromEnv).
	// Any command: a binary, an interpreter, or `docker run ...` if the
	// developer packages the app that way.
	Start []string `yaml:"start" json:"start"`
	// Port the app serves its direct endpoints on (HEAIN_LISTEN).
	Port int `yaml:"port,omitempty" json:"port,omitempty"`
	// DataDirs the app persists to besides HEAIN_STATE_DIR (relative to
	// the app directory), inspected by C14.
	DataDirs []string `yaml:"data_dirs,omitempty" json:"data_dirs,omitempty"`
	// Endpoints: one sample request per endpoint the suite should call.
	Endpoints []Call `yaml:"endpoints,omitempty" json:"endpoints,omitempty"`
	// Jobs: one sample job per execution: job capability.
	Jobs []JobCase `yaml:"jobs,omitempty" json:"jobs,omitempty"`
	P5   *P5Case   `yaml:"p5,omitempty" json:"p5,omitempty"`
	P7   *P7Case   `yaml:"p7,omitempty" json:"p7,omitempty"`
	// Companions are other apps the app needs in order to work (for
	// example the module heain-job orchestrates), each a directory with
	// its own conformance.yaml (build, start, manifest), relative to the
	// app directory. They are built, enrolled and started alongside the
	// app but are not under test.
	Companions []string `yaml:"companions,omitempty" json:"companions,omitempty"`
	// Deps is filled in by the runner (not read from YAML).
	Deps []Dep `yaml:"-" json:"deps,omitempty"`
}

// Dep is a companion app as the runner started it.
type Dep struct {
	Dir      string   `json:"dir"`
	AppID    string   `json:"app_id"`
	Instance string   `json:"instance"`
	Port     int      `json:"port"`
	Manifest string   `json:"manifest"`
	Build    []string `json:"build,omitempty"`
	Start    []string `json:"start"`
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
	if len(c.Start) == 0 {
		return c, fmt.Errorf("conformance.yaml: start (the command that runs the app) is required")
	}
	return c, nil
}
