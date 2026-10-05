// Package manifest loads and validates the Application Profile manifest v1
// (HEAIN spec 01-manifest.md). An app ships exactly one manifest
// (heain-app.yaml, or the same structure as JSON). The SDK refuses to start
// an app whose manifest is invalid; heain-core validates it again at
// registration with the same rules.
package manifest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Manifest is the manifest v1. Pointer booleans tell "missing" from
// "false": formal and ai.used are never inferred or defaulted.
type Manifest struct {
	ManifestVersion int              `json:"manifest_version" yaml:"manifest_version"`
	App             AppInfo          `json:"app" yaml:"app"`
	Capabilities    []Capability     `json:"capabilities" yaml:"capabilities"`
	Endpoints       []Endpoint       `json:"endpoints,omitempty" yaml:"endpoints,omitempty"`
	Uses            []Use            `json:"uses,omitempty" yaml:"uses,omitempty"`
	DataClasses     []DataClass      `json:"data_classes,omitempty" yaml:"data_classes,omitempty"`
	Lanes           Lanes            `json:"lanes,omitempty" yaml:"lanes,omitempty"`
	Offline         *Offline         `json:"offline,omitempty" yaml:"offline,omitempty"`
	Plugins         []map[string]any `json:"plugins,omitempty" yaml:"plugins,omitempty"`
	Resources       map[string]any   `json:"resources,omitempty" yaml:"resources,omitempty"`
	AISidecars      []map[string]any `json:"ai_sidecars,omitempty" yaml:"ai_sidecars,omitempty"`
}

type AppInfo struct {
	ID          string  `json:"id" yaml:"id"`
	Version     string  `json:"version" yaml:"version"`
	Group       string  `json:"group" yaml:"group"`
	Description string  `json:"description,omitempty" yaml:"description,omitempty"`
	API         string  `json:"api" yaml:"api"`
	SDK         SDKInfo `json:"sdk" yaml:"sdk"`
}

type SDKInfo struct {
	Name    string `json:"name" yaml:"name"`
	Version string `json:"version" yaml:"version"`
}

type Capability struct {
	Name         string   `json:"name" yaml:"name"`
	Version      int      `json:"version" yaml:"version"`
	Formal       *bool    `json:"formal" yaml:"formal"`
	Execution    string   `json:"execution" yaml:"execution"`
	InputSchema  string   `json:"input_schema,omitempty" yaml:"input_schema,omitempty"`
	OutputSchema string   `json:"output_schema,omitempty" yaml:"output_schema,omitempty"`
	Lane         string   `json:"lane,omitempty" yaml:"lane,omitempty"`
	AI           AIInfo   `json:"ai" yaml:"ai"`
	DataClasses  []string `json:"data_classes,omitempty" yaml:"data_classes,omitempty"`
}

type AIInfo struct {
	Used            *bool      `json:"used" yaml:"used"`
	Model           *ModelInfo `json:"model,omitempty" yaml:"model,omitempty"`
	ReasoningRecord string     `json:"reasoning_record,omitempty" yaml:"reasoning_record,omitempty"`
}

type ModelInfo struct {
	Name    string `json:"name" yaml:"name"`
	Version string `json:"version" yaml:"version"`
}

type Endpoint struct {
	Method     string `json:"method" yaml:"method"`
	Path       string `json:"path" yaml:"path"`
	Capability string `json:"capability" yaml:"capability"`
	Formal     *bool  `json:"formal" yaml:"formal"`
}

// Use is one declared dependency. App and each capability may be a
// pattern where "*" stands for any run of characters (decided 2026-10-06
// for orchestrators such as heain-job, which serve modules they cannot
// list in advance): {app: "*", capabilities: ["*.split", "*.merge"]}.
type Use struct {
	App          string   `json:"app" yaml:"app"`
	Capabilities []string `json:"capabilities" yaml:"capabilities"`
}

// Matches reports whether u declares capability of app.
func (u Use) Matches(app, capability string) bool {
	if !globMatch(u.App, app) {
		return false
	}
	for _, c := range u.Capabilities {
		if globMatch(c, capability) {
			return true
		}
	}
	return false
}

// DependsOn reports whether the manifest declares capability of app as a
// dependency (exact names or patterns).
func (m Manifest) DependsOn(app, capability string) bool {
	for _, u := range m.Uses {
		if u.Matches(app, capability) {
			return true
		}
	}
	return false
}

// UsesCapability reports whether any dependency entry covers capability
// (for job submission, where core, not the caller, picks the provider).
// NodeLocalCapabilities lists the capabilities that handle a data class
// declared sovereignty: node-local (spec 05 C9). Core admits their
// providers only from its own node and never leases their jobs elsewhere.
func (m Manifest) NodeLocalCapabilities() []string {
	local := map[string]bool{}
	for _, d := range m.DataClasses {
		if d.Sovereignty == "node-local" {
			local[d.Name] = true
		}
	}
	var out []string
	for _, c := range m.Capabilities {
		for _, dc := range c.DataClasses {
			if local[dc] {
				out = append(out, c.Name)
				break
			}
		}
	}
	return out
}

func (m Manifest) UsesCapability(capability string) bool {
	for _, u := range m.Uses {
		for _, c := range u.Capabilities {
			if globMatch(c, capability) {
				return true
			}
		}
	}
	return false
}

// globMatch matches s against pattern, where "*" stands for any run of
// characters (dots included).
func globMatch(pattern, s string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == s
	}
	parts := strings.Split(pattern, "*")
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for i := 1; i < len(parts)-1; i++ {
		j := strings.Index(s, parts[i])
		if j < 0 {
			return false
		}
		s = s[j+len(parts[i]):]
	}
	return strings.HasSuffix(s, parts[len(parts)-1])
}

var usePatRe = regexp.MustCompile(`^[a-z0-9*]([a-z0-9._*-]*)$`)

type DataClass struct {
	Name            string    `json:"name" yaml:"name"`
	Sovereignty     string    `json:"sovereignty" yaml:"sovereignty"`
	Retention       Retention `json:"retention,omitempty" yaml:"retention,omitempty"`
	RawStorage      string    `json:"raw_storage,omitempty" yaml:"raw_storage,omitempty"`
	CryptoShred     bool      `json:"crypto_shred,omitempty" yaml:"crypto_shred,omitempty"`
	Trust           string    `json:"trust,omitempty" yaml:"trust,omitempty"`
	EncryptedAtRest *bool     `json:"encrypted_at_rest,omitempty" yaml:"encrypted_at_rest,omitempty"`
}

type Retention struct {
	Max string `json:"max,omitempty" yaml:"max,omitempty"`
	Min string `json:"min,omitempty" yaml:"min,omitempty"`
}

type Lanes struct {
	Unlinkable [][]string `json:"unlinkable,omitempty" yaml:"unlinkable,omitempty"`
}

type Offline struct {
	// Allowed: nil = not declared; a list, even an empty one, limits
	// what may run while the node is standalone.
	Allowed []string `json:"allowed" yaml:"allowed"`
	Journal string   `json:"journal,omitempty" yaml:"journal,omitempty"`
}

// Error codes (spec 02 §10).
const (
	CodeManifestInvalid       = "manifest_invalid"
	CodeManifestFormalMissing = "manifest_formal_missing"
	CodeAPIUnsupported        = "api_unsupported"
)

// ValidationError lists every reason a manifest was rejected.
type ValidationError struct {
	Code    string   `json:"error"`
	Reasons []string `json:"reasons"`
}

func (e *ValidationError) Error() string { return e.Code + ": " + strings.Join(e.Reasons, "; ") }

// Load reads a manifest from a .yaml/.yml or .json file (same schema,
// decided 2026-10-05). Unknown fields are refused, so a typo such as
// "fromal" cannot silently drop a required field.
func Load(path string) (Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, err
	}
	return Parse(raw, strings.ToLower(filepath.Ext(path)))
}

// Parse decodes a manifest; ext is ".json", ".yaml" or ".yml".
func Parse(raw []byte, ext string) (Manifest, error) {
	var m Manifest
	switch ext {
	case ".json":
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&m); err != nil {
			return m, &ValidationError{Code: CodeManifestInvalid, Reasons: []string{"manifest JSON: " + err.Error()}}
		}
	case ".yaml", ".yml":
		dec := yaml.NewDecoder(bytes.NewReader(raw))
		dec.KnownFields(true)
		if err := dec.Decode(&m); err != nil {
			return m, &ValidationError{Code: CodeManifestInvalid, Reasons: []string{"manifest YAML: " + err.Error()}}
		}
	default:
		return m, fmt.Errorf("manifest: unknown file type %q (use .yaml, .yml or .json)", ext)
	}
	return m, nil
}

// SupportedAPIs are the App API majors this SDK speaks.
var SupportedAPIs = []string{"v1"}

var (
	appIDRe  = regexp.MustCompile(`^[a-z0-9-]{3,63}$`)
	semverRe = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
	capRe    = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*$`)
)

var sovereignties = map[string]bool{"global": true, "regional": true, "zone-local": true, "node-local": true}

// Validate applies spec 01 §4 rules 1-9, the same rules heain-core applies
// at registration (rule 10, app.id conflict, needs the core's registry).
func Validate(m Manifest) error {
	var formal, invalid []string
	bad := func(f string, a ...any) { invalid = append(invalid, fmt.Sprintf(f, a...)) }

	if m.ManifestVersion != 1 {
		bad("manifest_version must be 1")
	}
	if !appIDRe.MatchString(m.App.ID) {
		bad("app.id must match [a-z0-9-]{3,63}")
	}
	if !semverRe.MatchString(m.App.Version) {
		bad("app.version must be semver")
	}
	if m.App.Group != "base" && m.App.Group != "domain" {
		bad("app.group must be base or domain")
	}
	if m.App.SDK.Name == "" || m.App.SDK.Version == "" {
		bad("app.sdk.name and app.sdk.version are required")
	}
	if len(m.Capabilities) == 0 {
		bad("at least one capability is required")
	}

	caps := map[string]Capability{}
	lanesUsed := map[string]bool{}
	direct := map[string]bool{}
	for i, c := range m.Capabilities {
		at := fmt.Sprintf("capabilities[%d]", i)
		if c.Name == "" || !capRe.MatchString(c.Name) {
			bad("%s.name must be a dotted lowercase name", at)
		} else if _, dup := caps[c.Name]; dup {
			bad("%s.name %q is declared twice", at, c.Name)
		}
		caps[c.Name] = c
		if c.Version < 1 {
			bad("%s.version must be >= 1", at)
		}
		if c.Formal == nil {
			formal = append(formal, fmt.Sprintf("%s (%s).formal is missing", at, c.Name))
		}
		switch c.Execution {
		case "direct":
			direct[c.Name] = true
		case "job":
		default:
			bad("%s.execution must be direct or job", at)
		}
		if c.AI.Used == nil {
			bad("%s.ai.used is required", at)
		} else if *c.AI.Used && (c.AI.Model == nil || c.AI.Model.Name == "" || c.AI.Model.Version == "") {
			bad("%s: ai.used is true but ai.model.name/version is missing", at)
		}
		if rr := c.AI.ReasoningRecord; rr != "" && rr != "required" && rr != "optional" {
			bad("%s.ai.reasoning_record must be required or optional", at)
		}
		if c.Lane != "" {
			lanesUsed[c.Lane] = true
		}
	}

	hasEndpoint := map[string]bool{}
	for i, e := range m.Endpoints {
		at := fmt.Sprintf("endpoints[%d]", i)
		if e.Formal == nil {
			formal = append(formal, fmt.Sprintf("%s (%s %s).formal is missing", at, e.Method, e.Path))
		}
		if e.Method == "" || e.Path == "" || !strings.HasPrefix(e.Path, "/") {
			bad("%s needs method and an absolute path", at)
		}
		if _, ok := caps[e.Capability]; !ok {
			bad("%s references unknown capability %q", at, e.Capability)
		}
		hasEndpoint[e.Capability] = true
	}
	for name := range direct {
		if !hasEndpoint[name] {
			bad("capability %q is execution: direct but has no endpoint", name)
		}
	}

	for i, pair := range m.Lanes.Unlinkable {
		if len(pair) != 2 || pair[0] == pair[1] {
			bad("lanes.unlinkable[%d] must be a pair of two different lanes", i)
			continue
		}
		for _, l := range pair {
			if !lanesUsed[l] {
				bad("lanes.unlinkable[%d] uses undeclared lane %q", i, l)
			}
		}
	}

	dcs := map[string]bool{}
	for i, d := range m.DataClasses {
		at := fmt.Sprintf("data_classes[%d]", i)
		dcs[d.Name] = true
		if d.Name == "" {
			bad("%s.name is required", at)
		}
		if !sovereignties[d.Sovereignty] {
			bad("%s.sovereignty must be global, regional, zone-local or node-local", at)
		}
		var maxD, minD time.Duration
		var errMax, errMin error
		if d.Retention.Max != "" {
			if maxD, errMax = ParseRetention(d.Retention.Max); errMax != nil {
				bad("%s.retention.max: %v", at, errMax)
			}
		}
		if d.Retention.Min != "" {
			if minD, errMin = ParseRetention(d.Retention.Min); errMin != nil {
				bad("%s.retention.min: %v", at, errMin)
			}
		}
		if d.Retention.Max != "" && d.Retention.Min != "" && errMax == nil && errMin == nil && maxD < minD {
			bad("%s.retention.max is below retention.min", at)
		}
		if d.Trust != "" && d.Trust != "trusted" && d.Trust != "untrusted_source" {
			bad("%s.trust must be trusted or untrusted_source", at)
		}
		if d.EncryptedAtRest != nil && !*d.EncryptedAtRest {
			bad("%s.encrypted_at_rest must be true for persisted data", at)
		}
	}
	for _, c := range m.Capabilities {
		for _, dc := range c.DataClasses {
			if !dcs[dc] {
				bad("capability %q uses undeclared data class %q", c.Name, dc)
			}
		}
	}

	for i, u := range m.Uses {
		if u.App == "" || !usePatRe.MatchString(u.App) {
			bad("uses[%d].app must be an app id or a pattern with *", i)
		}
		if len(u.Capabilities) == 0 {
			bad("uses[%d] lists no capabilities", i)
		}
		for _, c := range u.Capabilities {
			if !usePatRe.MatchString(c) {
				bad("uses[%d] capability %q must be a capability name or a pattern with *", i, c)
			}
		}
	}

	if m.Offline != nil {
		for _, a := range m.Offline.Allowed {
			if _, ok := caps[a]; !ok {
				bad("offline.allowed lists unknown capability %q", a)
			}
		}
		if j := m.Offline.Journal; j != "" && j != "required" && j != "none" {
			bad("offline.journal must be required or none")
		}
	}

	if len(formal) > 0 {
		return &ValidationError{Code: CodeManifestFormalMissing, Reasons: append(formal, invalid...)}
	}
	if len(invalid) > 0 {
		return &ValidationError{Code: CodeManifestInvalid, Reasons: invalid}
	}
	supported := false
	for _, a := range SupportedAPIs {
		if m.App.API == a {
			supported = true
		}
	}
	if !supported {
		return &ValidationError{Code: CodeAPIUnsupported, Reasons: []string{fmt.Sprintf("app.api %q is not supported (supported: %v)", m.App.API, SupportedAPIs)}}
	}
	return nil
}

// CheckSDK checks that app.sdk names this SDK and that its version range
// includes version (e.g. ">=1.0.0 <2.0.0"; space-separated, each one of
// >=, >, <=, <, = or a bare version).
func CheckSDK(m Manifest, name, version string) error {
	if m.App.SDK.Name != name {
		return &ValidationError{Code: CodeManifestInvalid, Reasons: []string{fmt.Sprintf("app.sdk.name is %q; this SDK is %q", m.App.SDK.Name, name)}}
	}
	ok, err := SatisfiesRange(version, m.App.SDK.Version)
	if err != nil {
		return &ValidationError{Code: CodeManifestInvalid, Reasons: []string{"app.sdk.version: " + err.Error()}}
	}
	if !ok {
		return &ValidationError{Code: CodeManifestInvalid, Reasons: []string{fmt.Sprintf("app.sdk.version %q does not include this SDK's version %s", m.App.SDK.Version, version)}}
	}
	return nil
}

// SatisfiesRange reports whether version v satisfies every constraint in r.
func SatisfiesRange(v, r string) (bool, error) {
	if !semverRe.MatchString(v) {
		return false, fmt.Errorf("%q is not semver", v)
	}
	fields := strings.Fields(r)
	if len(fields) == 0 {
		return false, fmt.Errorf("empty version range")
	}
	for _, f := range fields {
		op, ver := "=", f
		for _, o := range []string{">=", "<=", ">", "<", "="} {
			if strings.HasPrefix(f, o) {
				op, ver = o, strings.TrimPrefix(f, o)
				break
			}
		}
		if !semverRe.MatchString(ver) {
			return false, fmt.Errorf("%q is not a version constraint", f)
		}
		c := CompareSemver(v, ver)
		pass := map[string]bool{">=": c >= 0, "<=": c <= 0, ">": c > 0, "<": c < 0, "=": c == 0}[op]
		if !pass {
			return false, nil
		}
	}
	return true, nil
}

// ParseRetention accepts Go durations plus a "d" (day) suffix, e.g. "30d".
func ParseRetention(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil || n < 0 {
			return 0, fmt.Errorf("%q is not a duration", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%q is not a duration", s)
	}
	return d, nil
}

// CompareSemver returns -1, 0 or 1 (pre-release and build ignored).
func CompareSemver(a, b string) int {
	pa, pb := semverParts(a), semverParts(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func semverParts(v string) [3]int {
	var out [3]int
	core := strings.SplitN(strings.SplitN(v, "+", 2)[0], "-", 2)[0]
	for i, p := range strings.SplitN(core, ".", 3) {
		out[i], _ = strconv.Atoi(p)
	}
	return out
}

// Capability returns the declared capability called name.
func (m Manifest) Capability(name string) (Capability, bool) {
	for _, c := range m.Capabilities {
		if c.Name == name {
			return c, true
		}
	}
	return Capability{}, false
}
