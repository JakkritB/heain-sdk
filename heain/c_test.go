package heain

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/heainframework/heain-sdk/core"
	"github.com/heainframework/heain-sdk/internal/testpki"
)

// fake3 is a fake core for jobs, P5, P7, mode and journal.
type fake3 struct {
	mu        sync.Mutex
	events    []map[string]any
	submits   []string // idempotency keys seen
	failFirst int32    // answer 503 to this many submits / journal writes
	jobs      []map[string]any
	claimed   []string // capabilities asked for, per claim
	done      map[string]map[string]any
	journal   []map[string]any
	mode      map[string]any
	polls     int
}

func (f *fake3) h(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	f.mu.Lock()
	defer f.mu.Unlock()
	busy := func() bool {
		if atomic.AddInt32(&f.failFirst, -1) >= 0 {
			w.WriteHeader(503)
			_, _ = w.Write([]byte(`{"error":{"code":"internal","message":"busy","retryable":true}}`))
			return true
		}
		return false
	}
	p := r.URL.Path
	switch {
	case p == "/v1/app/info":
		_, _ = w.Write([]byte(`{"core_version":"1.3.0","api_versions":["v1"],"node_id":"G"}`))
	case p == "/v1/app/register":
		_, _ = w.Write([]byte(`{"registration_id":"x","status":"active","heartbeat_interval_s":30}`))
	case p == "/v1/app/mode":
		_ = json.NewEncoder(w).Encode(f.mode)
	case p == "/v1/app/audit/events":
		f.events = append(f.events, body)
		w.WriteHeader(202)
	case p == "/v1/app/ai/reasoning":
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"record_id":"` + body["record_id"].(string) + `"}`))
	case p == "/v1/app/jobs":
		f.submits = append(f.submits, r.Header.Get("Idempotency-Key"))
		if busy() {
			return
		}
		w.WriteHeader(202)
		_, _ = w.Write([]byte(`{"ticket_id":"t-1","trace_id":"tr-1"}`))
	case p == "/v1/app/jobs/claim":
		caps, _ := body["capabilities"].([]any)
		var cs []string
		for _, c := range caps {
			cs = append(cs, c.(string))
		}
		f.claimed = append(f.claimed, strings.Join(cs, ","))
		for i, j := range f.jobs {
			for _, c := range cs {
				if j["capability"] == c {
					f.jobs = append(f.jobs[:i], f.jobs[i+1:]...)
					j["lease_id"], j["lease_expires_at"] = "L-"+j["ticket_id"].(string), time.Now().Add(time.Minute)
					_ = json.NewEncoder(w).Encode(j)
					return
				}
			}
		}
		f.mu.Unlock()
		time.Sleep(50 * time.Millisecond)
		f.mu.Lock()
		w.WriteHeader(204)
	case strings.HasPrefix(p, "/v1/app/jobs/") && (strings.HasSuffix(p, "/complete") || strings.HasSuffix(p, "/fail")):
		parts := strings.Split(p, "/")
		body["op"] = parts[5]
		f.done[parts[4]] = body
		_, _ = w.Write([]byte(`{}`))
	case strings.HasPrefix(p, "/v1/app/jobs/"):
		_, _ = w.Write([]byte(`{"ticket_id":"t-1","state":"completed","output_b64":"` + base64.StdEncoding.EncodeToString([]byte("out")) + `"}`))
	case p == "/v1/app/journal/events":
		f.journal = append(f.journal, body)
		if busy() {
			return
		}
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"seq":1,"hlc":"1.0","duplicate":false}`))
	case p == "/v1/app/policy/propose":
		_, _ = w.Write([]byte(`{"action_id":"appp5-1","result":"WAITING_APPROVAL"}`))
	case p == "/v1/app/policy/appp5-1":
		f.polls++
		res := "WAITING_APPROVAL"
		if f.polls >= 2 {
			res = "APPROVED"
		}
		_, _ = w.Write([]byte(`{"action_id":"appp5-1","result":"` + res + `"}`))
	case p == "/v1/app/broadcast":
		_, _ = w.Write([]byte(`{"action_id":"p7-x-` + body["discovery_id"].(string) + `","result":"WAITING_APPROVAL"}`))
	default:
		_, _ = w.Write([]byte(`{}`))
	}
}

const workerManifest = `manifest_version: 1
app: {id: work-app, version: 1.0.0, group: domain, api: v1, sdk: {name: heain-sdk-go, version: ">=1.0.0"}}
capabilities:
  - {name: img.resize, version: 1, formal: true, execution: job, ai: {used: false}}
  - {name: img.label, version: 1, formal: true, execution: job, ai: {used: true, model: {name: m, version: "1"}}}
  - {name: img.note, version: 1, formal: false, execution: job, ai: {used: false}}
  - {name: img.view, version: 1, formal: true, execution: direct, ai: {used: false}}
  - {name: img.offline, version: 1, formal: true, execution: direct, ai: {used: false}}
endpoints:
  - {method: GET, path: /v1/view, capability: img.view, formal: true}
  - {method: GET, path: /v1/offline, capability: img.offline, formal: true}
uses:
  - {app: other-app, capabilities: [img.upscale]}
offline: {allowed: [img.offline, img.note], journal: required}
`

func startFake3(t *testing.T, f *fake3) (*App, *testpki.PKI, string) {
	t.Helper()
	p := testpki.New(t)
	_, _, corePair := p.Issue(t, "core", "G")
	if f.done == nil {
		f.done = map[string]map[string]any{}
	}
	if f.mode == nil {
		f.mode = map[string]any{"mode": "normal"}
	}
	cs := httptest.NewUnstartedServer(http.HandlerFunc(f.h))
	cs.TLS = &tls.Config{Certificates: []tls.Certificate{corePair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: p.Pool()}
	cs.StartTLS()
	t.Cleanup(cs.Close)
	cert, key, _ := p.IssueApp(t, "work", "work-app.w1")
	mp := filepath.Join(t.TempDir(), "m.yaml")
	_ = os.WriteFile(mp, []byte(workerManifest), 0o644)
	state := t.TempDir()
	a, err := Start(context.Background(), Options{ManifestPath: mp, InstanceID: "w1", StateDir: state, ModePoll: 50 * time.Millisecond,
		Core: core.Config{URL: cs.URL, NodeID: "G", CertFile: cert, KeyFile: key, CAFile: p.CAFile}, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close(context.Background()) })
	return a, p, mp
}

func TestSubmit(t *testing.T) {
	f := &fake3{failFirst: 1}
	a, _, _ := startFake3(t, f)
	ctx := context.Background()
	if _, err := a.Submit(ctx, JobRequest{Capability: "x.undeclared"}); !errors.Is(err, ErrNotDeclared) {
		t.Fatalf("undeclared: %v", err)
	}
	if len(f.submits) != 0 {
		t.Fatal("an undeclared capability must not reach core")
	}
	tk, err := a.Submit(ctx, JobRequest{Capability: "img.upscale", Payload: []byte("p")})
	if err != nil || tk.TicketID != "t-1" {
		t.Fatalf("submit: %v %v", tk, err)
	}
	if len(f.submits) != 2 || f.submits[0] == "" || f.submits[0] != f.submits[1] {
		t.Fatalf("a retried submit must reuse its idempotency key: %v", f.submits)
	}
	s, err := a.WaitJob(ctx, "t-1")
	if err != nil || string(s.Output) != "out" || !s.Done() {
		t.Fatalf("wait: %+v %v", s, err)
	}
}

func TestWorker(t *testing.T) {
	f := &fake3{}
	f.jobs = []map[string]any{
		{"ticket_id": "ok", "capability": "img.resize", "trace_id": "tr-ok", "payload_b64": base64.StdEncoding.EncodeToString([]byte("abc"))},
		{"ticket_id": "perm", "capability": "img.resize", "trace_id": "tr-p", "payload_b64": base64.StdEncoding.EncodeToString([]byte("bad"))},
		{"ticket_id": "flaky", "capability": "img.resize", "trace_id": "tr-f", "payload_b64": base64.StdEncoding.EncodeToString([]byte("flaky"))},
		{"ticket_id": "norec", "capability": "img.label", "trace_id": "tr-n", "payload_b64": base64.StdEncoding.EncodeToString([]byte("forget"))},
		{"ticket_id": "rec", "capability": "img.label", "trace_id": "tr-r", "payload_b64": base64.StdEncoding.EncodeToString([]byte("x"))},
		{"ticket_id": "note", "capability": "img.note", "trace_id": "tr-nt", "payload_b64": ""},
		{"ticket_id": "panic", "capability": "img.note", "trace_id": "tr-pa", "payload_b64": base64.StdEncoding.EncodeToString([]byte("panic"))},
	}
	a, _, _ := startFake3(t, f)
	w := a.NewWorker()
	w.Wait = time.Second
	if err := w.Handle("img.view", nil); err == nil {
		t.Fatal("a direct capability cannot be a job handler")
	}
	var seen []byte
	_ = w.Handle("img.resize", func(ctx context.Context, j *Job) ([]byte, error) {
		switch string(j.Payload) {
		case "bad":
			return nil, Permanent(errors.New("corrupt image"))
		case "flaky":
			return nil, errors.New("gpu busy")
		}
		seen = j.Payload
		if TraceID(ctx) != "tr-ok" {
			t.Errorf("job ctx trace = %q", TraceID(ctx))
		}
		return []byte("resized:" + string(j.Payload)), nil
	})
	_ = w.Handle("img.label", func(ctx context.Context, j *Job) ([]byte, error) {
		if string(j.Payload) != "forget" {
			if _, err := a.Reason(ctx, Decision{Capability: "img.label", Input: j.Payload, Decision: "cat", Role: "advisory"}); err != nil {
				return nil, err
			}
		}
		return []byte("label"), nil
	})
	_ = w.Handle("img.note", func(ctx context.Context, j *Job) ([]byte, error) {
		if string(j.Payload) == "panic" {
			panic("boom")
		}
		return []byte("noted"), nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = w.Run(ctx) }()
	for i := 0; i < 100; i++ {
		f.mu.Lock()
		n := len(f.done)
		f.mu.Unlock()
		if n == 7 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	f.mu.Lock()
	defer f.mu.Unlock()
	want := map[string]string{"ok": "complete", "perm": "fail", "flaky": "fail", "norec": "fail", "rec": "complete", "note": "complete", "panic": "fail"}
	for tk, op := range want {
		if f.done[tk]["op"] != op {
			t.Fatalf("job %s: %v, want %s", tk, f.done[tk], op)
		}
	}
	if out, _ := base64.StdEncoding.DecodeString(f.done["ok"]["output_b64"].(string)); string(out) != "resized:abc" {
		t.Fatalf("output %q", out)
	}
	if string(seen) != "\x00\x00\x00" {
		t.Fatalf("the payload must be wiped after the handler: %q", seen)
	}
	if f.done["perm"]["retryable"] != false || f.done["flaky"]["retryable"] != true || f.done["norec"]["retryable"] != false || f.done["panic"]["retryable"] != true {
		t.Fatalf("retryable flags: %v %v %v %v", f.done["perm"], f.done["flaky"], f.done["norec"], f.done["panic"])
	}
	if ids, _ := f.done["rec"]["reasoning_record_ids"].([]any); len(ids) != 1 {
		t.Fatalf("complete must list the record: %v", f.done["rec"])
	}
	outcomes := map[string]string{}
	for _, e := range f.events {
		outcomes[e["detail"].(map[string]any)["ticket_id"].(string)] = e["outcome"].(string)
	}
	wantOut := map[string]string{"ok": "ok", "perm": "error:job_failed", "flaky": "error:job_failed", "norec": "error:reasoning_record_missing", "rec": "ok"}
	if len(f.events) != 5 {
		t.Fatalf("formal jobs give one event each, the non-formal none: %d events %v", len(f.events), outcomes)
	}
	for tk, o := range wantOut {
		if outcomes[tk] != o {
			t.Fatalf("job %s outcome %q, want %q", tk, outcomes[tk], o)
		}
	}
}

func TestModeOffline(t *testing.T) {
	f := &fake3{}
	a, _, _ := startFake3(t, f)
	changed := make(chan Mode, 4)
	a.OnModeChange(func(_, cur Mode) { changed <- cur })
	srv := a.NewServer()
	ok := func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{}`)) }
	_ = srv.HandleFunc("GET /v1/view", ok)
	_ = srv.HandleFunc("GET /v1/offline", ok)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, l) }()
	f.mu.Lock()
	f.mode = map[string]any{"mode": "standalone", "lost_parent": "G0", "deny_capabilities": []string{"img.note"}}
	f.mu.Unlock()
	select {
	case m := <-changed:
		if !m.Standalone() || m.LostParent != "G0" {
			t.Fatalf("mode: %+v", m)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no mode change seen")
	}
	if a.AllowedNow("img.view") || !a.AllowedNow("img.offline") || a.AllowedNow("img.note") {
		t.Fatal("offline: view is not in offline.allowed, offline is, note is denied by the admin policy")
	}
	cl, _ := a.appClient("work-app.w1")
	get := func(path string) int {
		resp, err := cl.Get("https://" + l.Addr().String() + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if get("/v1/view") != 409 || get("/v1/offline") != 200 {
		t.Fatal("standalone: /v1/view must be refused, /v1/offline served")
	}
	f.mu.Lock()
	refused := 0
	for _, e := range f.events {
		if e["outcome"] == "refused:standalone_not_allowed" {
			refused++
		}
	}
	f.mu.Unlock()
	if refused != 1 {
		t.Fatalf("the refusal must be audited once (%d)", refused)
	}
	// the worker does not claim a capability not allowed offline
	w := a.NewWorker()
	w.Wait = time.Second
	_ = w.Handle("img.resize", func(context.Context, *Job) ([]byte, error) { return nil, nil })
	wctx, wcancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	_ = w.Run(wctx)
	wcancel()
	f.mu.Lock()
	n := len(f.claimed)
	f.mu.Unlock()
	if n != 0 {
		t.Fatalf("claimed while not allowed offline: %d", n)
	}
	f.mu.Lock()
	f.mode = map[string]any{"mode": "normal"}
	f.mu.Unlock()
	select {
	case m := <-changed:
		if m.Standalone() {
			t.Fatal("expected normal")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no return to normal seen")
	}
}

func TestJournalSeq(t *testing.T) {
	f := &fake3{}
	a, _, _ := startFake3(t, f)
	ctx := WithTrace(context.Background(), "tr-j", "")
	for i := 0; i < 2; i++ {
		if e, err := a.Journal(ctx, "vote.counted", "", map[string]any{"n": i}); err != nil || e.AppSeq != uint64(i+1) {
			t.Fatalf("journal %d: %+v %v", i, e, err)
		}
	}
	atomic.StoreInt32(&f.failFirst, 1)
	if e, err := a.Journal(ctx, "vote.counted", "", map[string]any{"n": 3}); err != nil || e.AppSeq != 3 {
		t.Fatalf("journal 3: %+v %v", e, err)
	}
	f.mu.Lock()
	seqs := []any{}
	for _, j := range f.journal {
		seqs = append(seqs, j["app_seq"])
	}
	f.mu.Unlock()
	if len(seqs) != 4 || seqs[2] != seqs[3] || seqs[3] != float64(3) {
		t.Fatalf("a retry must reuse its app_seq: %v", seqs)
	}
	// a restarted instance continues the counter
	b := &App{Manifest: a.Manifest, Instance: a.Instance, opts: a.opts}
	if n, _ := b.nextAppSeq(); n != 4 {
		t.Fatalf("after restart app_seq = %d, want 4", n)
	}
}

func TestPolicyAndBroadcast(t *testing.T) {
	f := &fake3{}
	a, _, _ := startFake3(t, f)
	ctx := context.Background()
	PolicyPoll = 20 * time.Millisecond
	r, err := a.Propose(ctx, Proposal{Type: "grant.extend", Category: CategoryAllowlist})
	if err != nil || !r.Waiting() {
		t.Fatalf("propose: %+v %v", r, err)
	}
	r, err = a.WaitPolicy(ctx, r.ActionID)
	if err != nil || !r.Allowed() || r.Result != ResultApproved {
		t.Fatalf("wait: %+v %v", r, err)
	}
	if _, err := a.Propose(ctx, Proposal{}); err == nil {
		t.Fatal("type and category are required")
	}
	b, err := a.Broadcast(ctx, "d1", "zone-a", map[string]any{"rule": "r"})
	if err != nil || b.ActionID != "p7-x-d1" || !b.Waiting() {
		t.Fatalf("broadcast: %+v %v", b, err)
	}
}
