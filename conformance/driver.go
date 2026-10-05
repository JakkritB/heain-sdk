package conformance

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/heainframework/heain-sdk/core"
	"github.com/heainframework/heain-sdk/manifest"
	"github.com/heainframework/heain-sdk/provision"
)

// ---- report ----

// Check is one verified statement.
type Check struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Skipped bool   `json:"skipped,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// Group is one conformance group (C1-C14).
type Group struct {
	ID     string  `json:"id"`
	Name   string  `json:"name"`
	Status string  `json:"status"` // pass | fail | n/a
	Checks []Check `json:"checks"`
}

// Report is the suite's result.
type Report struct {
	App      string    `json:"app"`
	Version  string    `json:"version"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished,omitempty"`
	Groups   []*Group  `json:"groups"`
}

// GroupNames are spec 05 §2.
var GroupNames = map[string]string{"C1": "Manifest", "C2": "Transport", "C3": "Registration", "C4": "Jobs", "C5": "Formal logging",
	"C6": "AI records", "C7": "Unlinkability", "C8": "Policy (P5)", "C9": "Sovereignty (P7)", "C10": "Offline", "C11": "Compatibility",
	"C12": "Base-app usage", "C13": "Plaintext locality", "C14": "Encryption at rest"}

func (r *Report) group(id string) *Group {
	for _, g := range r.Groups {
		if g.ID == id {
			return g
		}
	}
	g := &Group{ID: id, Name: GroupNames[id], Status: "n/a"}
	r.Groups = append(r.Groups, g)
	sort.Slice(r.Groups, func(i, j int) bool { return groupNum(r.Groups[i].ID) < groupNum(r.Groups[j].ID) })
	return g
}

func groupNum(id string) int { var n int; fmt.Sscanf(id, "C%d", &n); return n }

func (g *Group) add(c Check) {
	g.Checks = append(g.Checks, c)
	switch {
	case !c.OK && !c.Skipped:
		g.Status = "fail"
	case c.OK && !c.Skipped && g.Status == "n/a":
		g.Status = "pass"
	}
}

// Passed reports whether no group failed.
func (r *Report) Passed() bool {
	for _, g := range r.Groups {
		if g.Status == "fail" {
			return false
		}
	}
	return true
}

// Text is the readable summary.
func (r *Report) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "heain conformance -- %s %s\n\n", r.App, r.Version)
	for _, g := range r.Groups {
		fmt.Fprintf(&b, "%-4s %-20s %s\n", g.ID, g.Name, strings.ToUpper(g.Status))
		for _, c := range g.Checks {
			mark := "ok  "
			switch {
			case c.Skipped:
				mark = "skip"
			case !c.OK:
				mark = "FAIL"
			}
			fmt.Fprintf(&b, "       [%s] %s", mark, c.Name)
			if c.Detail != "" {
				fmt.Fprintf(&b, " -- %s", c.Detail)
			}
			b.WriteString("\n")
		}
	}
	verdict := "PASS"
	if !r.Passed() {
		verdict = "FAIL"
	}
	fmt.Fprintf(&b, "\nRESULT: %s\n", verdict)
	return b.String()
}

// ---- driver ----

// Driver runs the checks from inside the node's network namespace.
type Driver struct {
	Shared   string
	Conf     Conf
	Man      manifest.Manifest
	AppReg   string // <app-id>.<instance>
	Rep      *Report
	Instance string

	ca         *x509.CertPool
	clients    map[string]*http.Client
	markers    map[string]bool
	ctlN       int
	mu         sync.Mutex
	probeReg   string
	ProbeCert  string
	ProbeKey   string
	probeCore  map[string]*core.Client
	appBase    string // https://127.0.0.1:<port>
	traceLanes map[string]map[string]bool

	// Host does what the driver cannot: start, stop, pause the app, restart
	// core, the proxy between W and G (set by the runner).
	Host func(action string, args map[string]string) HostResult
	// DataDirs are the directories core and the app persist to (C14).
	DataDirs []string
}

// NewDriver loads the shared state written by the host.
func NewDriver(shared string) (*Driver, error) {
	d := &Driver{Shared: shared, clients: map[string]*http.Client{}, markers: map[string]bool{}, Instance: "a1",
		probeCore: map[string]*core.Client{}, traceLanes: map[string]map[string]bool{}}
	raw, err := os.ReadFile(filepath.Join(shared, "app", "conformance.json"))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &d.Conf); err != nil {
		return nil, err
	}
	if d.Man, err = manifest.Load(filepath.Join(shared, "app", "heain-app.yaml")); err != nil {
		return nil, err
	}
	d.AppReg = d.Man.App.ID + "." + d.Instance
	if d.ca, err = core.LoadPool(filepath.Join(shared, "certs", "ca.pem")); err != nil {
		return nil, err
	}
	d.Rep = &Report{App: d.Man.App.ID, Version: d.Man.App.Version, Started: time.Now().UTC()}
	if raw, err := os.ReadFile(filepath.Join(shared, "report.json")); err == nil {
		_ = json.Unmarshal(raw, d.Rep)
	}
	return d, nil
}

// Save writes report.json and report.txt.
func (d *Driver) Save() {
	d.Rep.Finished = time.Now().UTC()
	_ = writeJSONFile(filepath.Join(d.Shared, "report.json"), d.Rep)
	_ = writeShared(filepath.Join(d.Shared, "report.txt"), []byte(d.Rep.Text()), 0o644)
}

func (d *Driver) check(group, name string, ok bool, detail string, a ...any) {
	if len(a) > 0 {
		detail = fmt.Sprintf(detail, a...)
	}
	d.Rep.group(group).add(Check{Name: name, OK: ok, Detail: detail})
	st := "PASS"
	if !ok {
		st = "FAIL"
	}
	log.Printf("%s %s: %s %s", st, group, name, detail)
}

func (d *Driver) skip(group, name, detail string) {
	d.Rep.group(group).add(Check{Name: name, OK: true, Skipped: true, Detail: detail})
	log.Printf("SKIP %s: %s %s", group, name, detail)
}

// marker registers plaintext that must never leave the app (C6, C13, C14).
func (d *Driver) marker(s string) {
	if len(s) < 6 {
		return
	}
	d.mu.Lock()
	d.markers[s] = true
	var all []string
	for m := range d.markers {
		all = append(all, m)
	}
	d.mu.Unlock()
	sort.Strings(all)
	_ = writeShared(filepath.Join(d.Shared, "markers.txt"), []byte(strings.Join(all, "\n")+"\n"), 0o644)
}

// client returns an mTLS client for a named certificate in certs/ (or a
// full path pair), verifying the server against the harness CA with
// serverName (empty = no name check, for app endpoints).
func (d *Driver) client(certFile, keyFile, serverName string) *http.Client {
	k := certFile + "|" + serverName
	d.mu.Lock()
	defer d.mu.Unlock()
	if c, ok := d.clients[k]; ok {
		return c
	}
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Printf("driver: loading %s: %v", certFile, err)
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, RootCAs: d.ca, ServerName: serverName}
	if serverName == "" {
		tc.InsecureSkipVerify = true // app certificates carry no names; the identity is not under test here
	}
	c := &http.Client{Timeout: 40 * time.Second, Transport: &http.Transport{TLSClientConfig: tc, Proxy: nil}}
	d.clients[k] = c
	return c
}

func (d *Driver) certs(name string) (string, string) {
	return filepath.Join(d.Shared, "certs", name+".pem"), filepath.Join(d.Shared, "certs", name+".key")
}

// as calls a core as a named harness identity (admin, approver-1).
func (d *Driver) as(who, base, node, method, path string, body any) (int, []byte) {
	c, k := d.certs(who)
	return d.call(d.client(c, k, node), method, base+path, body, nil)
}

func (d *Driver) call(c *http.Client, method, url string, body any, hdr map[string]string) (int, []byte) {
	st, out, _, _ := d.callH(c, method, url, body, hdr)
	return st, out
}

func (d *Driver) callH(c *http.Client, method, url string, body any, hdr map[string]string) (int, []byte, http.Header, error) {
	var rd io.Reader
	if body != nil {
		if b, ok := body.([]byte); ok {
			rd = bytes.NewReader(b)
		} else {
			raw, _ := json.Marshal(body)
			rd = bytes.NewReader(raw)
		}
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		return 0, nil, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, []byte(err.Error()), nil, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out, resp.Header, nil
}

func jsonMap(b []byte) map[string]any {
	m := map[string]any{}
	_ = json.Unmarshal(b, &m)
	return m
}

func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func errCode(b []byte) string {
	m := jsonMap(b)
	if e, ok := m["error"].(map[string]any); ok {
		return str(e, "code")
	}
	return ""
}

// waitFor polls f until it is true or the timeout passes.
func waitFor(timeout time.Duration, f func() bool) bool {
	end := time.Now().Add(timeout)
	for {
		if f() {
			return true
		}
		if time.Now().After(end) {
			return false
		}
		time.Sleep(time.Second)
	}
}

// ---- host actions (process steps the runner does) ----

// HostResult is the host's answer to an action.
type HostResult struct {
	OK   bool   `json:"ok"`
	Exit int    `json:"exit"`
	Out  string `json:"out"`
}

func (d *Driver) host(action string, args map[string]string) HostResult {
	log.Printf("driver: host action %s %v", action, args)
	if d.Host == nil {
		return HostResult{Out: "no host"}
	}
	return d.Host(action, args)
}

// ---- core helpers ----

// Event is one record of core's audit chain.
type Event struct {
	Action string         `json:"Action"`
	Actor  string         `json:"Actor"`
	Result string         `json:"Result"`
	Detail map[string]any `json:"Detail"`
}

func (d *Driver) audit(base, node string) []Event {
	_, out := d.as("admin", base, node, "GET", "/v1/admin/audit?limit=20000", nil)
	var r struct {
		Records []struct {
			Event Event `json:"event"`
		} `json:"records"`
	}
	_ = json.Unmarshal(out, &r)
	evs := make([]Event, 0, len(r.Records))
	for _, x := range r.Records {
		evs = append(evs, x.Event)
	}
	return evs
}

func detail2(e Event) map[string]any { m, _ := e.Detail["detail"].(map[string]any); return m }

// appStatus finds an instance in GET /v1/admin/apps.
func (d *Driver) appStatus(base, node, appID, inst string) string {
	_, out := d.as("admin", base, node, "GET", "/v1/admin/apps", nil)
	var v any
	_ = json.Unmarshal(out, &v)
	var found string
	var walk func(x any)
	walk = func(x any) {
		switch t := x.(type) {
		case map[string]any:
			if t["app_id"] == appID && t["instance_id"] == inst {
				found, _ = t["status"].(string)
				return
			}
			for _, v := range t {
				walk(v)
			}
		case []any:
			for _, v := range t {
				walk(v)
			}
		}
	}
	walk(v)
	return found
}

// approveRegistrations approves every waiting app.register action.
func (d *Driver) approveWaiting(base, node, typ string) int {
	_, out := d.as("approver-1", base, node, "GET", "/v1/admin/policy/pending", nil)
	var r struct {
		Actions []struct {
			ID   string `json:"ID"`
			Type string `json:"Type"`
		} `json:"actions"`
	}
	_ = json.Unmarshal(out, &r)
	n := 0
	for _, a := range r.Actions {
		if a.Type == typ {
			if st, _ := d.as("approver-1", base, node, "POST", "/v1/admin/policy/"+a.ID+"/approve", nil); st == 200 {
				n++
			}
		}
	}
	return n
}

func (d *Driver) decide(base, node, id string, approve bool) int {
	op := "reject"
	if approve {
		op = "approve"
	}
	st, _ := d.as("approver-1", base, node, "POST", "/v1/admin/policy/"+id+"/"+op, nil)
	return st
}

func (d *Driver) setSystem(base, node, key string, value any) int {
	st, _ := d.as("admin", base, node, "PUT", "/v1/admin/config/system/"+key, map[string]any{"value": value})
	return st
}

// enrollToken asks core for a provisioning token for label and writes it
// to file (the app picks it up through HEAIN_ENROLL_TOKEN).
func (d *Driver) enrollToken(base, node, label, file string) error {
	var st int
	var out []byte
	waitFor(90*time.Second, func() bool { // right after start the node may not be the Raft leader yet
		st, out = d.as("admin", base, node, "POST", "/provision/token", map[string]any{"label": label})
		return st == 200 || st == 201
	})
	if st != 200 && st != 201 {
		return fmt.Errorf("provision/token %d %s", st, out)
	}
	return writeShared(file, out, 0o600)
}

// probe enrolls (once) and registers the driver's own app,
// conformance-probe.<inst>, at the core base, and approves it.
func (d *Driver) probe(ctx context.Context, enrollBase, enrollNode, base, node, inst, manifestYAML string) (*core.Client, error) {
	dir := filepath.Join(d.Shared, "probe-"+inst)
	cert, key := filepath.Join(dir, "app.pem"), filepath.Join(dir, "app.key")
	if _, err := os.Stat(cert); err != nil {
		tokFile := filepath.Join(dir, "token.json")
		if err := d.enrollToken(enrollBase, enrollNode, "conformance-probe."+inst, tokFile); err != nil {
			return nil, err
		}
		var tok struct {
			Token, BootstrapCertPEM, BootstrapKeyPEM string
		}
		raw, _ := os.ReadFile(tokFile)
		var t map[string]string
		_ = json.Unmarshal(raw, &t)
		tok.Token, tok.BootstrapCertPEM, tok.BootstrapKeyPEM = t["token"], t["bootstrap_cert_pem"], t["bootstrap_key_pem"]
		c, _ := d.certs("ca")
		if _, err := provision.Enroll(ctx, provision.Request{CoreURL: enrollBase, CoreNodeID: enrollNode, CAFile: c,
			ChainFile: filepath.Join(d.Shared, "certs", "prov.pem"), Token: tok.Token, BootstrapCertPEM: tok.BootstrapCertPEM,
			BootstrapKeyPEM: tok.BootstrapKeyPEM, AppID: "conformance-probe", InstanceID: inst, OutDir: dir}); err != nil {
			return nil, fmt.Errorf("probe enrolment: %w", err)
		}
		chownHost(cert)
		chownHost(key)
	}
	d.ProbeCert, d.ProbeKey, d.probeReg = cert, key, "conformance-probe."+inst
	m, err := manifest.Parse([]byte(manifestYAML), ".yaml")
	if err != nil {
		return nil, err
	}
	caFile, _ := d.certs("ca")
	cl, err := core.New(core.Config{URL: base, NodeID: node, CertFile: cert, KeyFile: key, CAFile: caFile})
	if err != nil {
		return nil, err
	}
	var reg core.Registration
	// a Worker checks app certificates with its Master: wait until it has joined the farm
	waitFor(120*time.Second, func() bool { reg, err = cl.Register(ctx, m, inst, ""); return err == nil })
	if err != nil {
		return nil, fmt.Errorf("probe register: %w", err)
	}
	if reg.Status != "active" {
		d.approveWaiting(base, node, "app.register")
	}
	if !waitFor(30*time.Second, func() bool { r, err := cl.Heartbeat(ctx); return err == nil && r.Status == "active" }) {
		return nil, fmt.Errorf("probe not admitted")
	}
	go func() { // keep it live
		for {
			time.Sleep(3 * time.Second)
			_, _ = cl.Heartbeat(context.Background())
		}
	}()
	d.probeCore[base] = cl
	return cl, nil
}

// probeHTTP is an mTLS client with the probe's app certificate.
func (d *Driver) probeHTTP(serverName string) *http.Client {
	return d.client(d.ProbeCert, d.ProbeKey, serverName)
}

func (d *Driver) probeDo(base, node, method, path string, body any) (int, []byte) {
	return d.call(d.probeHTTP(node), method, base+path, body, nil)
}

// ---- manifest helpers ----

var segRe = regexp.MustCompile(`\{[^}]+\}`)

// endpointFor matches a concrete call to the manifest endpoint it serves.
func (d *Driver) endpointFor(method, path string) (manifest.Endpoint, manifest.Capability, bool) {
	for _, e := range d.Man.Endpoints {
		if !strings.EqualFold(e.Method, method) {
			continue
		}
		pat := "^" + segRe.ReplaceAllString(e.Path, "[^/]+") + "$"
		if ok, _ := regexp.MatchString(pat, path); ok {
			c, _ := d.Man.Capability(e.Capability)
			return e, c, true
		}
	}
	return manifest.Endpoint{}, manifest.Capability{}, false
}

func isFormal(b *bool) bool { return b != nil && *b }
func aiUsed(c manifest.Capability) bool {
	return c.AI.Used != nil && *c.AI.Used
}

// RemoteClaim tries a job claim with the probe's certificate from another
// host (C13); core must refuse it.
func RemoteClaim(shared, coreURL string) (int, string, error) { // coreURL: core through this machine's LAN address
	return remotePost(shared, coreURL+"/v1/app/jobs/claim", `{"wait_s":1}`)
}

// RemoteRegister registers the app's manifest from another host (C9): core
// must refuse a manifest with node-local data before anything else.
func RemoteRegister(shared, coreURL, manifestJSON string) (int, string, error) {
	return remotePost(shared, coreURL+"/v1/app/register", `{"instance_id":"c9-remote","endpoint_base":"https://127.0.0.1:1","manifest":`+manifestJSON+`}`)
}

func remotePost(shared, u, body string) (int, string, error) {
	pool, err := core.LoadPool(filepath.Join(shared, "certs", "ca.pem"))
	if err != nil {
		return 0, "", err
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(shared, "probe-p1", "app.pem"), filepath.Join(shared, "probe-p1", "app.key"))
	if err != nil {
		return 0, "", err
	}
	c := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{pair}, RootCAs: pool, ServerName: "G"}}}
	resp, err := c.Post(u, "application/json", strings.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), nil
}

// startDeps enrolls and starts the companion apps (not under test) and
// waits until core admits them.
func (d *Driver) startDeps(enrollBase, enrollNode, base, node string) bool {
	if len(d.Conf.Deps) == 0 {
		return true
	}
	for _, dp := range d.Conf.Deps {
		if err := d.enrollToken(enrollBase, enrollNode, dp.AppID+"."+dp.Instance, filepath.Join(d.Shared, "enroll", dp.Instance+".json")); err != nil {
			log.Printf("driver: companion token: %v", err)
			return false
		}
	}
	d.host("deps_start", nil)
	return waitFor(120*time.Second, func() bool {
		d.approveWaiting(base, node, "app.register")
		for _, dp := range d.Conf.Deps {
			if d.appStatus(base, node, dp.AppID, dp.Instance) != "active" {
				return false
			}
		}
		return true
	})
}
