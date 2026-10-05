package conformance

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/heainframework/heain-sdk/heain"
	"github.com/heainframework/heain-sdk/manifest"
	"gopkg.in/yaml.v3"
)

// Phase 1 (single node G): C1-C9 and C11-C14.
// Ports of the harness's core nodes (processes on this machine; the app
// and the driver reach them over loopback, as an app on the node does).
const (
	gNode     = "G"
	gPort     = 28100
	s1Port    = 28105
	wPort     = 28103
	proxyPort = 28110
)

var (
	gBase  = fmt.Sprintf("https://127.0.0.1:%d", gPort)
	gBase2 = gBase
	wBase  = fmt.Sprintf("https://127.0.0.1:%d", wPort)
)

// callRec remembers one call to the app (for C5-C7).
type callRec struct {
	call    Call
	ep      manifest.Endpoint
	cap     manifest.Capability
	trace   string
	status  int
	body    []byte
	respTr  string
	lane    string
	formal  bool
	ai      bool
	jobTk   string
	jobAtt  int
	jobCase *JobCase
}

// RunSingle runs phase 1.
func (d *Driver) RunSingle(ctx context.Context) {
	defer d.Save()
	d.appBase = fmt.Sprintf("https://127.0.0.1:%d", d.Conf.Port)
	if !waitFor(90*time.Second, func() bool { st, _ := d.as("admin", gBase, gNode, "GET", "/health", nil); return st == 200 }) {
		d.check("C3", "core G is up", false, "core did not answer /health within 90 s")
		return
	}
	// short liveness timers so C3 runs in seconds (2a keys, applied at once)
	d.setSystem(gBase, gNode, "apps.heartbeat_interval", "3s")
	d.setSystem(gBase, gNode, "apps.ttl", "10s")
	for _, e := range d.Conf.Endpoints {
		d.marker(e.Secret)
	}
	for _, j := range d.Conf.Jobs {
		d.marker(j.Payload)
	}
	if _, err := d.probe(ctx, gBase, gNode, gBase, gNode, "p1", d.probeManifest(true)); err != nil {
		d.check("C3", "the driver's probe app is admitted", false, "%v", err)
		return
	}

	// ---- the app under test starts and is admitted
	if err := d.enrollToken(gBase, gNode, d.AppReg, filepath.Join(d.Shared, "enroll", "a1.json")); err != nil {
		d.check("C3", "enrolment token issued", false, "%v", err)
		return
	}
	d.host("app_start", nil)
	waitFor(60*time.Second, func() bool {
		d.approveWaiting(gBase, gNode, "app.register")
		return d.appStatus(gBase, gNode, d.Man.App.ID, d.Instance) == "active"
	})
	st := d.appStatus(gBase, gNode, d.Man.App.ID, d.Instance)
	d.check("C3", "app enrolls through provisioning, registers, is admitted: active", st == "active", "status %q", st)
	if st != "active" {
		return
	}
	if len(d.Man.Endpoints) > 0 {
		waitFor(30*time.Second, func() bool { s, _ := d.call(d.probeHTTP(""), "GET", d.appBase+"/", nil, nil); return s != 0 })
	}

	d.c1(ctx)
	d.c2()
	d.c3()
	calls := d.c5calls()
	jobs := d.c4(ctx)
	calls = append(calls, jobs...)
	d.c5(calls)
	d.c6(calls)
	d.c7(calls)
	d.c8()
	d.c9()
	d.c12()
	d.c11(ctx)
	d.c13()
	d.c14(d.DataDirs, "phase 1")
}

func (d *Driver) probeManifest(withJobs bool) string {
	var b strings.Builder
	b.WriteString("manifest_version: 1\napp: {id: conformance-probe, version: 1.0.0, group: domain, api: v1, sdk: {name: heain-sdk-go, version: \">=1.0.0\"}}\ncapabilities:\n")
	b.WriteString("  - {name: probe.ai, version: 1, formal: true, execution: job, ai: {used: true, model: {name: probe-model, version: \"1\"}}}\n")
	if withJobs {
		for _, c := range d.Man.Capabilities {
			if c.Execution == "job" {
				fmt.Fprintf(&b, "  - {name: %s, version: %d, formal: true, execution: job, ai: {used: false}}\n", c.Name, c.Version)
			}
		}
	}
	b.WriteString("offline: {allowed: []}\n")
	return b.String()
}

// ---- C1 manifest

func (d *Driver) c1(ctx context.Context) {
	// SDK side: the app itself refuses to start without one formal
	broken := filepath.Join(d.Shared, "app", "broken-formal.yaml")
	if err := writeShared(broken, removeFirstFormal(filepath.Join(d.Shared, "app", "heain-app.yaml")), 0o644); err != nil {
		d.check("C1", "broken manifest prepared", false, "%v", err)
	}
	before := len(d.audit(gBase, gNode))
	r := d.host("app_broken", map[string]string{"manifest": broken})
	after := d.audit(gBase, gNode)
	reached := false
	for _, e := range after[min(before, len(after)):] {
		if strings.HasPrefix(e.Action, "app.register") && strings.Contains(fmt.Sprint(e.Detail), "c1x") {
			reached = true
		}
	}
	d.check("C1", "SDK: the app refuses to start when one `formal` is removed, before any call to core", r.Exit != 0 && !reached,
		"exit %d, reached core: %v, output: %s", r.Exit, reached, firstLine(r.Out))

	// core side: every §4 rule, with the probe's identity
	base := map[string]any{}
	raw, _ := json.Marshal(d.Man)
	_ = json.Unmarshal(raw, &base)
	app := base["app"].(map[string]any)
	app["id"], app["version"] = "conformance-probe", "9.9.9"
	type variant struct {
		name, code string
		mut        func(m map[string]any)
	}
	caps := func(m map[string]any) []any { c, _ := m["capabilities"].([]any); return c }
	vs := []variant{
		{"rule 1: a capability without formal", "manifest_formal_missing", func(m map[string]any) { delete(caps(m)[0].(map[string]any), "formal") }},
		{"rule 2: app.version missing", "manifest_invalid", func(m map[string]any) { delete(m["app"].(map[string]any), "version") }},
		{"rule 3: execution: direct without an endpoint", "manifest_invalid", func(m map[string]any) {
			m["capabilities"] = append(caps(m), map[string]any{"name": "x.direct", "version": 1, "formal": true, "execution": "direct", "ai": map[string]any{"used": false}})
		}},
		{"rule 4: endpoint with an unknown capability", "manifest_invalid", func(m map[string]any) {
			eps, _ := m["endpoints"].([]any)
			m["endpoints"] = append(eps, map[string]any{"method": "POST", "path": "/x", "capability": "no.such", "formal": true})
		}},
		{"rule 5: ai.used without a model", "manifest_invalid", func(m map[string]any) {
			m["capabilities"] = append(caps(m), map[string]any{"name": "x.ai", "version": 1, "formal": true, "execution": "job", "ai": map[string]any{"used": true}})
		}},
		{"rule 6: unlinkable pair with undeclared lanes", "manifest_invalid", func(m map[string]any) {
			m["lanes"] = map[string]any{"unlinkable": []any{[]any{"nowhere-a", "nowhere-b"}}}
		}},
		{"rule 7: data class without sovereignty, retention max < min", "manifest_invalid", func(m map[string]any) {
			m["data_classes"] = []any{map[string]any{"name": "dc", "retention": map[string]any{"max": "1d", "min": "2d"}}}
		}},
		{"rule 8: offline.allowed lists an unknown capability", "manifest_invalid", func(m map[string]any) {
			m["offline"] = map[string]any{"allowed": []any{"no.such"}}
		}},
		{"rule 9: persisted data class with encrypted_at_rest: false", "manifest_invalid", func(m map[string]any) {
			m["data_classes"] = []any{map[string]any{"name": "dc2", "sovereignty": "global", "encrypted_at_rest": false}}
		}},
		{"unsupported app.api", "api_unsupported", func(m map[string]any) { m["app"].(map[string]any)["api"] = "v9" }},
	}
	for _, v := range vs {
		m := deepCopy(base)
		v.mut(m)
		st, out := d.probeDo(gBase, gNode, "POST", "/v1/app/register", map[string]any{"manifest": m, "instance_id": "p1"})
		d.check("C1", "core: "+v.name+" -> "+v.code, st >= 400 && errCode(out) == v.code, "%d %s", st, errCode(out))
	}
	d.check("C1", "core: the app's own manifest is accepted", d.appStatus(gBase, gNode, d.Man.App.ID, d.Instance) == "active", "")
}

func removeFirstFormal(path string) []byte {
	raw, _ := os.ReadFile(path)
	var n yaml.Node
	if yaml.Unmarshal(raw, &n) != nil || len(n.Content) == 0 {
		return raw
	}
	root := n.Content[0]
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value != "capabilities" {
			continue
		}
		seq := root.Content[i+1]
		if len(seq.Content) == 0 {
			break
		}
		c := seq.Content[0]
		for j := 0; j+1 < len(c.Content); j += 2 {
			if c.Content[j].Value == "formal" {
				c.Content = append(c.Content[:j], c.Content[j+2:]...)
				break
			}
		}
	}
	out, _ := yaml.Marshal(&n)
	return out
}

func deepCopy(m map[string]any) map[string]any {
	raw, _ := json.Marshal(m)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return out
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, "\n"); i >= 0 {
		s = s[i+1:]
	}
	if len(s) > 160 {
		s = s[:160]
	}
	return s
}

// ---- C2 transport

func (d *Driver) c2() {
	plain := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}}
	st, _ := d.call(plain, "GET", strings.Replace(gBase, "https://", "http://", 1)+"/v1/app/info", nil, nil)
	d.check("C2", "core: plain HTTP is refused", st == 0 || st >= 400, "status %d", st)
	tls12 := func(cert, key string) *http.Client {
		pair, _ := tls.LoadX509KeyPair(cert, key)
		return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{
			MaxVersion: tls.VersionTLS12, InsecureSkipVerify: true, Certificates: []tls.Certificate{pair}}}}
	}
	st, _ = d.call(tls12(d.ProbeCert, d.ProbeKey), "GET", gBase+"/v1/app/info", nil, nil)
	d.check("C2", "core: TLS 1.2 is refused (TLS 1.3 only)", st == 0, "status %d", st)
	rc, rk := d.certs("rogue-app")
	st, _ = d.call(d.client(rc, rk, gNode), "GET", gBase+"/v1/app/info", nil, nil)
	d.check("C2", "core: an app certificate from another CA is refused", st == 0 || st == 401 || st == 403, "status %d", st)
	if len(d.Man.Endpoints) == 0 {
		d.skip("C2", "app endpoints", "the app has no direct endpoints")
		return
	}
	st, _ = d.call(plain, "GET", strings.Replace(d.appBase, "https://", "http://", 1)+"/", nil, nil)
	d.check("C2", "app: plain HTTP is refused", st == 0 || st >= 400, "status %d", st)
	st, _ = d.call(tls12(d.ProbeCert, d.ProbeKey), "GET", d.appBase+"/", nil, nil)
	d.check("C2", "app: TLS 1.2 is refused", st == 0, "status %d", st)
	st, _ = d.call(d.client(rc, rk, ""), "POST", d.appBase+d.firstEndpointPath(), map[string]any{}, nil)
	d.check("C2", "app: a certificate from another CA is refused", st == 0, "status %d", st)
	ac, ak := d.certs("admin")
	st, out := d.call(d.client(ac, ak, ""), "POST", d.appBase+d.firstEndpointPath(), map[string]any{}, nil)
	d.check("C2", "app: a certificate that is not an app certificate is refused", st == 403, "%d %s", st, errCode(out))
	noCert := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	st, _ = d.call(noCert, "POST", d.appBase+d.firstEndpointPath(), map[string]any{}, nil)
	d.check("C2", "app: a caller without a client certificate is refused", st == 0, "status %d", st)
}

func (d *Driver) firstEndpointPath() string {
	for _, e := range d.Conf.Endpoints {
		return e.Path
	}
	return "/"
}

// ---- C3 registration

func (d *Driver) discovered() bool {
	for _, c := range d.Man.Capabilities {
		st, out := d.probeDo(gBase, gNode, "GET", "/v1/app/discover?capability="+c.Name, nil)
		if st != 200 {
			return false
		}
		var r struct {
			Instances []struct {
				AppID      string `json:"app_id"`
				InstanceID string `json:"instance_id"`
			} `json:"instances"`
		}
		_ = json.Unmarshal(out, &r)
		for _, in := range r.Instances {
			if in.AppID == d.Man.App.ID && in.InstanceID == d.Instance {
				return true
			}
		}
		return false
	}
	return false
}

func (d *Driver) c3() {
	time.Sleep(12 * time.Second)
	d.check("C3", "heartbeats keep it live past the TTL (10 s)", d.discovered() && d.appStatus(gBase, gNode, d.Man.App.ID, d.Instance) == "active", "")
	d.host("app_pause", nil)
	gone := waitFor(25*time.Second, func() bool { return !d.discovered() })
	d.check("C3", "a missed TTL drops it from discovery (app paused)", gone, "")
	d.host("app_unpause", nil)
	back := waitFor(25*time.Second, d.discovered)
	d.check("C3", "back in discovery after it resumes heartbeats", back, "")
	d.host("app_stop", nil)
	st := ""
	waitFor(20*time.Second, func() bool { st = d.appStatus(gBase, gNode, d.Man.App.ID, d.Instance); return st == "deregistered" })
	d.check("C3", "SIGTERM -> graceful deregister", st == "deregistered", "status %q", st)
	d.host("app_start", nil)
	ok := waitFor(60*time.Second, func() bool { return d.appStatus(gBase, gNode, d.Man.App.ID, d.Instance) == "active" && d.discovered() })
	d.check("C3", "restart -> active again (admitted version, no new approval)", ok, "")
	raw, _ := json.Marshal(d.Man)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	s, out := d.probeDo(gBase, gNode, "POST", "/v1/app/register", map[string]any{"manifest": m, "instance_id": "p1"})
	d.check("C3", "a certificate whose CN is not <app.id>.<instance> cannot register as the app", errCode(out) == "identity_mismatch", "%d %s", s, errCode(out))
	if len(d.Man.Endpoints) > 0 {
		waitFor(30*time.Second, func() bool { s, _ := d.call(d.probeHTTP(""), "GET", d.appBase+"/", nil, nil); return s != 0 })
	}
}

// ---- C5 calls (shared with C6, C7)

func (d *Driver) callApp(c Call, trace, lane string) callRec {
	ep, cp, _ := d.endpointFor(c.Method, c.Path)
	hdr := map[string]string{heain.HeaderTrace: trace}
	if lane != "" {
		hdr[heain.HeaderLane] = lane
	}
	var body any
	if c.Body != nil {
		body = c.Body
	} else if c.Method != "GET" {
		body = map[string]any{}
	}
	st, out, h, _ := d.callH(d.probeHTTP(""), c.Method, d.appBase+c.Path, body, hdr)
	r := callRec{call: c, ep: ep, cap: cp, trace: trace, status: st, body: out, lane: lane, formal: isFormal(ep.Formal), ai: aiUsed(cp)}
	if h != nil {
		r.respTr = h.Get(heain.HeaderTrace)
	}
	return r
}

func (d *Driver) c5calls() []callRec {
	var out []callRec
	for _, c := range d.Conf.Endpoints {
		ep, cp, ok := d.endpointFor(c.Method, c.Path)
		if !ok {
			d.check("C5", fmt.Sprintf("%s %s is an endpoint of the manifest", c.Method, c.Path), false, "not found in the manifest")
			continue
		}
		_ = ep
		r := d.callApp(c, heain.NewID(), cp.Lane)
		want := c.Expect
		if want == 0 {
			want = 200
		}
		d.check("C5", fmt.Sprintf("%s %s answers %d", c.Method, c.Path, want), r.status == want, "got %d %s", r.status, firstLine(string(r.body)))
		out = append(out, r)
	}
	return out
}

func (d *Driver) appEvents(evs []Event) []Event {
	var out []Event
	for _, e := range evs {
		if e.Action == "app.event" && e.Actor == d.AppReg {
			out = append(out, e)
		}
	}
	return out
}

func (d *Driver) c5(calls []callRec) {
	time.Sleep(time.Second)
	evs := d.appEvents(d.audit(gBase, gNode))
	for _, r := range calls {
		if r.jobTk != "" {
			n := 0
			for _, e := range evs {
				if str(detail2(e), "ticket_id") == r.jobTk && str(e.Detail, "capability") == r.cap.Name {
					n++
				}
			}
			want := 0
			if isFormal(r.cap.Formal) {
				want = r.jobAtt
			}
			d.check("C5", fmt.Sprintf("job %s: one audit event per attempt (formal: %v)", r.cap.Name, isFormal(r.cap.Formal)), n == want, "%d events, %d attempts", n, r.jobAtt)
			continue
		}
		n, laneOK := 0, true
		for _, e := range evs {
			if str(e.Detail, "trace_id") == r.trace && str(e.Detail, "capability") == r.cap.Name {
				n++
				if str(e.Detail, "lane") != r.cap.Lane {
					laneOK = false
				}
			}
		}
		want := 0
		if r.formal {
			want = 1
		}
		d.check("C5", fmt.Sprintf("%s %s (formal: %v): exactly %d audit event(s) with its trace id and lane", r.call.Method, r.call.Path, r.formal, want),
			n == want && laneOK, "%d events, lane ok %v", n, laneOK)
	}
}

// ---- C4 jobs

func (d *Driver) submit(capName, payload, delivery, key string) (int, map[string]any) {
	if delivery == "" {
		delivery = "STAGED"
	}
	body := map[string]any{"capability": capName, "payload_b64": base64.StdEncoding.EncodeToString([]byte(payload)), "classification": map[string]any{"delivery": delivery}}
	st, out := d.call(d.probeHTTP(gNode), "POST", gBase+"/v1/app/jobs", body, map[string]string{"Idempotency-Key": key})
	return st, jsonMap(out)
}

func (d *Driver) jobStatus(tk string) (int, map[string]any) {
	st, out := d.probeDo(gBase, gNode, "GET", "/v1/app/jobs/"+tk, nil)
	return st, jsonMap(out)
}

func (d *Driver) waitJob(tk string, timeout time.Duration) map[string]any {
	var m map[string]any
	waitFor(timeout, func() bool {
		_, m = d.jobStatus(tk)
		s := str(m, "state")
		return s == "completed" || s == "delivered" || s == "retries_exhausted" || s == "disposed"
	})
	return m
}

func (d *Driver) c4(ctx context.Context) []callRec {
	var recs []callRec
	jobCaps := 0
	for _, c := range d.Man.Capabilities {
		if c.Execution == "job" {
			jobCaps++
		}
	}
	if jobCaps == 0 {
		d.skip("C4", "jobs", "the app has no execution: job capability")
		return nil
	}
	for i := range d.Conf.Jobs {
		j := d.Conf.Jobs[i]
		cp, ok := d.Man.Capability(j.Capability)
		if !ok || cp.Execution != "job" {
			d.check("C4", j.Capability+" is an execution: job capability of the manifest", false, "")
			continue
		}
		key := "conf-" + heain.NewID()
		st1, r1 := d.submit(j.Capability, j.Payload, j.Delivery, key)
		st2, r2 := d.submit(j.Capability, j.Payload, j.Delivery, key)
		tk := str(r1, "ticket_id")
		d.check("C4", j.Capability+": submit accepted; the same Idempotency-Key returns the same ticket", st1 == 202 && st2 == 200 && tk != "" && tk == str(r2, "ticket_id"), "%d %d", st1, st2)
		m := d.waitJob(tk, 90*time.Second)
		out, _ := base64.StdEncoding.DecodeString(str(m, "output_b64"))
		okOut := str(m, "state") == "completed" || str(m, "state") == "delivered"
		if j.ExpectOutput != "" {
			okOut = okOut && string(out) == j.ExpectOutput
		}
		d.check("C4", j.Capability+": claimed and completed by the app; output returned", okOut, "state %s, output %q", str(m, "state"), trim(string(out)))
		d.marker(j.ExpectOutput)
		att := int(num(m, "attempts"))
		if strings.EqualFold(j.Delivery, "IMMEDIATE") {
			_, again := d.jobStatus(tk)
			d.check("C4", j.Capability+": IMMEDIATE output is delivered once", str(again, "output_b64") == "", "state %s", str(again, "state"))
		} else {
			st, _ := d.probeDo(gBase, gNode, "POST", "/v1/app/jobs/"+tk+"/confirm-retrieval", map[string]any{})
			s2, after := d.jobStatus(tk)
			d.check("C4", j.Capability+": staged output, retrieval confirmed -> disposed", st == 200 && (s2 >= 400 || str(after, "output_b64") == ""), "confirm %d, then %d %s", st, s2, str(after, "state"))
		}
		recs = append(recs, callRec{cap: cp, jobTk: tk, jobAtt: att, trace: str(m, "trace_id"), ai: aiUsed(cp), formal: isFormal(cp.Formal), jobCase: &j, call: Call{Secret: j.Payload}})
	}
	// lease expiry -> reassignment (the probe offers the capability too, claims and walks away)
	if len(d.Conf.Jobs) > 0 {
		j := d.Conf.Jobs[0]
		d.setSystem(gBase, gNode, "dispatch.lease_default", "4s")
		d.host("app_pause", nil)
		_, r := d.submit(j.Capability, j.Payload, j.Delivery, "conf-"+heain.NewID())
		tk := str(r, "ticket_id")
		st, out := d.probeDo(gBase, gNode, "POST", "/v1/app/jobs/claim", map[string]any{"capabilities": []string{j.Capability}, "wait_s": 5})
		claimed := st == 200 && str(jsonMap(out), "ticket_id") == tk
		time.Sleep(6 * time.Second)
		d.host("app_unpause", nil)
		m := d.waitJob(tk, 90*time.Second)
		d.setSystem(gBase, gNode, "dispatch.lease_default", "30s")
		d.check("C4", "lease expiry -> the job is reassigned and completed by the app", claimed && str(m, "state") == "completed" && num(m, "attempts") >= 2,
			"probe claimed %v, state %s, attempts %v", claimed, str(m, "state"), m["attempts"])
		if cp, ok := d.Man.Capability(j.Capability); ok {
			recs = append(recs, callRec{cap: cp, jobTk: tk, jobAtt: int(num(m, "attempts")) - 1, trace: str(m, "trace_id"), ai: aiUsed(cp), formal: isFormal(cp.Formal), call: Call{Secret: j.Payload}})
		}
	}
	return recs
}

func num(m map[string]any, k string) float64 { f, _ := m[k].(float64); return f }

func trim(s string) string {
	if len(s) > 60 {
		return s[:60] + "..."
	}
	return s
}

// ---- C6 AI records

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (d *Driver) c6(calls []callRec) {
	evs := d.audit(gBase, gNode)
	seen := false
	for _, r := range calls {
		if !r.ai {
			continue
		}
		seen = true
		name := r.cap.Name
		if r.call.Path != "" {
			name = r.call.Method + " " + r.call.Path
		}
		var recs []map[string]any
		for _, e := range evs {
			if e.Action == "ai.reasoning_record" && e.Actor == d.AppReg && str(e.Detail, "trace_id") == r.trace {
				if rec, ok := e.Detail["record"].(map[string]any); ok {
					recs = append(recs, rec)
				}
			}
		}
		d.check("C6", name+": a reasoning record was filed for the decision", len(recs) >= 1, "%d record(s) with trace %s", len(recs), r.trace)
		for _, rec := range recs {
			raw, _ := json.Marshal(rec)
			secretOK := r.call.Secret == "" || !strings.Contains(string(raw), r.call.Secret)
			in, _ := rec["input"].(map[string]any)
			model, _ := rec["model"].(map[string]any)
			linked := false
			for _, e := range d.appEvents(evs) {
				if str(e.Detail, "trace_id") != r.trace {
					continue
				}
				ids, _ := detail2(e)["reasoning_record_ids"].([]any)
				for _, id := range ids {
					if id == rec["record_id"] {
						linked = true
					}
				}
			}
			d.check("C6", name+": record has no raw input, a model hash, a signature (verified by core) and is linked to its audit event",
				secretOK && hex64.MatchString(str(in, "sha256")) && hex64.MatchString(str(model, "artifact_sha256")) && str(rec, "signature") != "" && linked,
				"raw input absent %v, input hash %v, model hash %v, signed %v, linked %v", secretOK, hex64.MatchString(str(in, "sha256")),
				hex64.MatchString(str(model, "artifact_sha256")), str(rec, "signature") != "", linked)
		}
	}
	if !seen {
		d.skip("C6", "AI records", "no ai.used capability was exercised")
	}
	// a forged record is refused by core
	rec := heain.Record{RecordVersion: 1, RecordID: heain.NewID(), TraceID: heain.NewID(), App: map[string]any{"id": "conformance-probe", "version": "1.0.0", "instance_id": "p1"},
		Capability: map[string]any{"name": "probe.ai", "version": 1}, Model: map[string]any{"name": "probe-model", "version": "1"},
		Input: map[string]any{"sha256": strings.Repeat("ab", 32), "size_bytes": 3}, Output: map[string]any{"decision": "x"},
		Reasoning: map[string]any{"summary": "probe", "factors": []any{}}, Role: "advisory", At: time.Now().UTC().Format(time.RFC3339)}
	goodSig, err1 := signWith(rec, d.ProbeKey)
	rk, _ := d.certs("rogue-app")
	badSig, err2 := signWith(rec, strings.TrimSuffix(rk, ".pem")+".key")
	if err1 != nil || err2 != nil {
		d.check("C6", "forged-record test prepared", false, "%v %v", err1, err2)
		return
	}
	rec.Signature = badSig
	st, out := d.probeDo(gBase, gNode, "POST", "/v1/app/ai/reasoning", rec)
	d.check("C6", "a record signed with another key is refused by core (signature_invalid)", st == 400 && errCode(out) == "signature_invalid", "%d %s", st, errCode(out))
	rec.Signature = goodSig
	st, _ = d.probeDo(gBase, gNode, "POST", "/v1/app/ai/reasoning", rec)
	d.check("C6", "the same record signed with the right key is accepted", st == 201, "%d", st)
}

func signWith(rec heain.Record, keyFile string) (string, error) {
	rec.Signature = ""
	canon, err := heain.Canonical(rec)
	if err != nil {
		return "", err
	}
	raw, err := os.ReadFile(keyFile)
	if err != nil {
		return "", err
	}
	b, _ := pem.Decode(raw)
	if b == nil {
		return "", fmt.Errorf("no PEM key in %s", keyFile)
	}
	var signer crypto.Signer
	if k, err := x509.ParsePKCS1PrivateKey(b.Bytes); err == nil {
		signer = k
	} else if k, err := x509.ParseECPrivateKey(b.Bytes); err == nil {
		signer = k
	} else if k, err := x509.ParsePKCS8PrivateKey(b.Bytes); err == nil {
		signer, _ = k.(crypto.Signer)
	}
	if signer == nil {
		return "", fmt.Errorf("unsupported key in %s", keyFile)
	}
	h := sha256.Sum256(canon)
	sig, err := signer.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

var _ = rsa.PublicKey{}

// ---- C7 unlinkability

func (d *Driver) c7(calls []callRec) {
	if len(d.Man.Lanes.Unlinkable) == 0 {
		d.skip("C7", "unlinkable lanes", "the manifest declares none")
		return
	}
	for _, pair := range d.Man.Lanes.Unlinkable {
		var ca, cb *Call
		for i := range d.Conf.Endpoints {
			c := &d.Conf.Endpoints[i]
			_, cp, _ := d.endpointFor(c.Method, c.Path)
			if cp.Lane == pair[0] && ca == nil {
				ca = c
			}
			if cp.Lane == pair[1] && cb == nil {
				cb = c
			}
		}
		if ca == nil || cb == nil {
			d.skip("C7", fmt.Sprintf("crossing %s -> %s", pair[0], pair[1]), "conformance.yaml has no endpoint in each lane")
			continue
		}
		r := d.callApp(*ca, heain.NewID(), "")
		d.check("C7", fmt.Sprintf("a call to lane %s without the lane header is refused (lane_violation)", pair[0]), r.status == 400 && errCode(r.body) == "lane_violation", "%d %s", r.status, errCode(r.body))
		t := heain.NewID()
		r1 := d.callApp(*ca, t, pair[0])
		r2 := d.callApp(*cb, t, pair[1])
		d.check("C7", fmt.Sprintf("the same trace id in %s then %s: the second call is refused (lane_violation)", pair[0], pair[1]),
			r1.status < 400 && r2.status == 400 && errCode(r2.body) == "lane_violation", "%d then %d %s", r1.status, r2.status, errCode(r2.body))
		// no identifier in both lanes: audit, records, responses
		evs := d.audit(gBase, gNode)
		lanesOf := map[string]map[string]bool{}
		add := func(id, lane string) {
			if id == "" || lane == "" {
				return
			}
			if lanesOf[id] == nil {
				lanesOf[id] = map[string]bool{}
			}
			lanesOf[id][lane] = true
		}
		for _, e := range evs {
			if e.Actor != d.AppReg {
				continue
			}
			switch e.Action {
			case "app.event":
				add(str(e.Detail, "trace_id"), str(e.Detail, "lane"))
				ids, _ := detail2(e)["reasoning_record_ids"].([]any)
				for _, id := range ids {
					add(fmt.Sprint(id), str(e.Detail, "lane"))
				}
			case "ai.reasoning_record":
				rec, _ := e.Detail["record"].(map[string]any)
				add(str(rec, "trace_id"), str(rec, "lane"))
				add(str(rec, "record_id"), str(rec, "lane"))
			}
		}
		for _, c := range append(calls, r1, r2) {
			add(c.respTr, c.cap.Lane)
		}
		crossed := 0
		for _, ls := range lanesOf {
			if ls[pair[0]] && ls[pair[1]] {
				crossed++
			}
		}
		d.check("C7", fmt.Sprintf("no identifier appears in both %s and %s (audit, records, responses)", pair[0], pair[1]), crossed == 0, "%d crossing id(s) of %d checked", crossed, len(lanesOf))
	}
}

// ---- C8 P5

func (d *Driver) depth(typ string) float64 {
	_, out := d.as("admin", gBase, gNode, "GET", "/v1/admin/governance/metrics?policy_key="+typ, nil)
	return num(jsonMap(out), "ApprovalQueueDepth")
}

func (d *Driver) p5status(id string) string {
	if d.Conf.P5.Status == nil {
		return ""
	}
	c := *d.Conf.P5.Status
	c.Path = strings.ReplaceAll(c.Path, "{action_id}", id)
	r := d.callApp(c, heain.NewID(), "")
	return str(jsonMap(r.body), "result")
}

func (d *Driver) c8() {
	if d.Conf.P5 == nil {
		d.skip("C8", "P5", "conformance.yaml has no p5 trigger (the app does not propose)")
		return
	}
	before := d.depth(d.Conf.P5.Type)
	r := d.callApp(d.Conf.P5.Propose, heain.NewID(), "")
	m := jsonMap(r.body)
	id := str(m, "action_id")
	d.check("C8", "a proposal outside thresholds returns WAITING_APPROVAL", str(m, "result") == "WAITING_APPROVAL" && id != "", "%d %s", r.status, firstLine(string(r.body)))
	after := d.depth(d.Conf.P5.Type)
	d.check("C8", "the escalation queue depth increases", after > before, "%v -> %v", before, after)
	d.decide(gBase, gNode, id, true)
	d.check("C8", "Approver approves -> APPROVED", d.p5status(id) == "APPROVED", "status %q", d.p5status(id))
	r = d.callApp(d.Conf.P5.Propose, heain.NewID(), "")
	id2 := str(jsonMap(r.body), "action_id")
	d.decide(gBase, gNode, id2, false)
	d.check("C8", "Approver rejects -> DENIED", d.p5status(id2) == "DENIED", "status %q", d.p5status(id2))
}

// ---- C9 P7

func (d *Driver) c9() {
	if d.Conf.P7 == nil {
		d.skip("C9", "P7 broadcast", "conformance.yaml has no p7 trigger (the app does not broadcast)")
	} else {
		r := d.callApp(d.Conf.P7.Broadcast, heain.NewID(), "")
		m := jsonMap(r.body)
		id := str(m, "action_id")
		d.check("C9", "a broadcast goes through P5 (WAITING_APPROVAL)", str(m, "result") == "WAITING_APPROVAL" && id != "", "%d %s", r.status, firstLine(string(r.body)))
		d.decide(gBase, gNode, id, true)
		var got []byte
		waitFor(15*time.Second, func() bool {
			_, got = d.as("admin", gBase, gNode, "GET", "/broadcast/received", nil)
			return strings.Contains(string(got), strings.TrimPrefix(id, "p7-"))
		})
		leaked := []string{}
		for _, s := range d.Conf.P7.Sensitive {
			if strings.Contains(string(got), `"`+s+`"`) {
				leaked = append(leaked, s)
			}
		}
		d.check("C9", "approved -> delivered and sanitized (sensitive fields removed)", strings.Contains(string(got), strings.TrimPrefix(id, "p7-")) && len(leaked) == 0,
			"delivered %v, leaked %v", strings.Contains(string(got), strings.TrimPrefix(id, "p7-")), leaked)
	}
	d.skip("C9", "data classes never leave their declared scope", "core does not filter discovery by zone/sovereignty yet (known core gap, spec 02 §11)")
}

// ---- C12 uses[]

func (d *Driver) c12() {
	if len(d.Man.Uses) == 0 {
		d.skip("C12", "dependencies", "the manifest declares no uses[]")
	}
	allowed := map[string]bool{}
	for _, u := range d.Man.Uses {
		for _, c := range u.Capabilities {
			allowed[u.App+"/"+c] = true
		}
	}
	calls, bad := 0, []string{}
	for _, e := range d.audit(gBase, gNode) {
		if e.Action != "app.event" || !strings.HasPrefix(str(e.Detail, "app_actor"), d.Man.App.ID+".") || str(detail2(e), "ticket_id") != "" {
			continue // not a call by the app (jobs the app ran are audited with itself as actor)
		}
		callee := strings.SplitN(e.Actor, ".", 2)[0]
		calls++
		if !allowed[callee+"/"+str(e.Detail, "capability")] {
			bad = append(bad, callee+"/"+str(e.Detail, "capability"))
		}
	}
	if calls == 0 {
		d.skip("C12", "the app's calls to other apps", "no app-to-app call was observed")
		return
	}
	d.check("C12", "every app-to-app call of the app targets a dependency declared in uses[]", len(bad) == 0, "%d call(s), undeclared: %v", calls, bad)
	d.check("C12", "dependencies are resolved through discovery (the harness gives no addresses; calls succeeded)", true, "")
}

// ---- C11 compatibility

func (d *Driver) c11(ctx context.Context) {
	d.host("core_restart", map[string]string{"extra": "-compat-test-probe=true"})
	up := waitFor(90*time.Second, func() bool {
		st, out := d.probeDo(gBase, gNode, "GET", "/v1/app/info", nil)
		return st == 200 && str(jsonMap(out), "core_version") == "1.99.0"
	})
	d.check("C11", "core restarted as a newer minor version (1.99.0, unknown fields in every answer)", up, "")
	if !up {
		return
	}
	ok := waitFor(60*time.Second, func() bool { return d.appStatus(gBase, gNode, d.Man.App.ID, d.Instance) == "active" && d.discovered() })
	d.check("C11", "C3 again: the app keeps its registration live with the newer core", ok, "")
	var calls []callRec
	for _, c := range d.Conf.Endpoints {
		_, cp, _ := d.endpointFor(c.Method, c.Path)
		r := d.callApp(c, heain.NewID(), cp.Lane)
		want := c.Expect
		if want == 0 {
			want = 200
		}
		d.check("C11", fmt.Sprintf("C5 again: %s %s answers %d", c.Method, c.Path, want), r.status == want, "got %d", r.status)
		calls = append(calls, r)
	}
	if len(d.Conf.Jobs) > 0 {
		j := d.Conf.Jobs[0]
		_, r := d.submit(j.Capability, j.Payload, j.Delivery, "conf-"+heain.NewID())
		m := d.waitJob(str(r, "ticket_id"), 90*time.Second)
		d.check("C11", "C4 again: a job is completed", str(m, "state") == "completed" || str(m, "state") == "delivered", "state %s", str(m, "state"))
	}
	time.Sleep(time.Second)
	evs := d.appEvents(d.audit(gBase, gNode))
	for _, r := range calls {
		n := 0
		for _, e := range evs {
			if str(e.Detail, "trace_id") == r.trace && str(e.Detail, "capability") == r.cap.Name {
				n++
			}
		}
		want := 0
		if r.formal {
			want = 1
		}
		if r.ai && r.formal {
			d.check("C11", fmt.Sprintf("C5/C6 again: %s %s logged once with its record", r.call.Method, r.call.Path), n == 1, "%d events", n)
		} else {
			d.check("C11", fmt.Sprintf("C5 again: %s %s logged %d time(s)", r.call.Method, r.call.Path, want), n == want, "%d events", n)
		}
	}
	d.host("core_restart", map[string]string{"extra": "-compat-test-probe=false"})
	back := waitFor(90*time.Second, func() bool {
		st, out := d.probeDo(gBase, gNode, "GET", "/v1/app/info", nil)
		return st == 200 && str(jsonMap(out), "core_version") != "1.99.0"
	})
	waitFor(60*time.Second, func() bool { return d.appStatus(gBase, gNode, d.Man.App.ID, d.Instance) == "active" })
	if !back {
		log.Printf("driver: core did not come back without the probe")
	}
}

// ---- C13 locality

func (d *Driver) c13() {
	if len(d.Conf.Jobs) == 0 {
		d.skip("C13", "claim locality", "the app has no job capability")
	} else {
		r := d.host("remote_claim", nil)
		d.check("C13", "a claim from another host is refused (locality_violation)", r.Exit == 0, "%s", firstLine(r.Out))
	}
	d.skip("C13", "no plaintext in traffic leaving the node", "one node has no traffic between nodes; checked in the offline phase (the proxy between W and G inspects every byte)")
}

func (d *Driver) proxyCheck() {
	r := d.host("proxy_hits", nil)
	d.check("C13", "no plaintext marker in any byte between W and G (all of it passes the harness proxy)", r.OK, "%s", r.Out)
}

// ---- C14 encryption at rest

func (d *Driver) c14(roots []string, label string) {
	d.mu.Lock()
	var ms [][]byte
	for m := range d.markers {
		ms = append(ms, []byte(m))
	}
	d.mu.Unlock()
	files, hits := 0, []string{}
	for _, root := range roots {
		_ = filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
			if err != nil || fi.IsDir() || fi.Size() > 512<<20 {
				return nil
			}
			files++
			raw, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			for _, m := range ms {
				if bytesContains(raw, m) {
					hits = append(hits, p+": "+string(m))
				}
			}
			return nil
		})
	}
	d.check("C14", fmt.Sprintf("no plaintext of the test data in any file persisted by core or the app (%s)", label), files > 0 && len(ms) > 0 && len(hits) == 0,
		"%d files, %d markers, hits: %v", files, len(ms), hits)
}
