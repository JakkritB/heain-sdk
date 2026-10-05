package heain

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heainframework/heain-sdk/core"
	"github.com/heainframework/heain-sdk/internal/testpki"
)

// fake2 is a fake core that records audit events and reasoning records and
// answers discovery from a fixed table.
type fake2 struct {
	mu      sync.Mutex
	events  []map[string]any
	records []map[string]any
	disco   map[string][]Instance
}

func (f *fake2) h(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.URL.Path == "/v1/app/info":
		_, _ = w.Write([]byte(`{"core_version":"1.3.0","api_versions":["v1"],"node_id":"G"}`))
	case r.URL.Path == "/v1/app/register":
		_, _ = w.Write([]byte(`{"registration_id":"x","status":"active","heartbeat_interval_s":30}`))
	case r.URL.Path == "/v1/app/audit/events":
		f.events = append(f.events, body)
		w.WriteHeader(202)
	case r.URL.Path == "/v1/app/ai/reasoning":
		f.records = append(f.records, body)
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"record_id":"` + body["record_id"].(string) + `"}`))
	case r.URL.Path == "/v1/app/discover":
		_ = json.NewEncoder(w).Encode(map[string]any{"instances": f.disco[r.URL.Query().Get("capability")]})
	default:
		_, _ = w.Write([]byte(`{}`))
	}
}

func (f *fake2) count() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.events), len(f.records)
}

const svcManifest = `manifest_version: 1
app: {id: svc-app, version: 1.0.0, group: domain, api: v1, sdk: {name: heain-sdk-go, version: ">=1.0.0"}}
capabilities:
  - {name: svc.greet, version: 1, formal: true, execution: direct, ai: {used: false}}
  - {name: svc.classify, version: 1, formal: true, execution: direct, ai: {used: true, model: {name: m1, version: "1"}}}
  - {name: id.check, version: 1, formal: true, execution: direct, lane: identity, ai: {used: false}}
  - {name: ballot.cast, version: 1, formal: true, execution: direct, lane: ballot, ai: {used: false}}
endpoints:
  - {method: POST, path: /v1/greet, capability: svc.greet, formal: true}
  - {method: GET, path: "/v1/greet/{id}", capability: svc.greet, formal: false}
  - {method: POST, path: /v1/classify, capability: svc.classify, formal: true}
  - {method: POST, path: /v1/classify-forgetful, capability: svc.classify, formal: true}
  - {method: POST, path: /v1/id, capability: id.check, formal: true}
  - {method: POST, path: /v1/ballot, capability: ballot.cast, formal: true}
lanes: {unlinkable: [[identity, ballot]]}
`

const callerManifest = `manifest_version: 1
app: {id: caller-app, version: 1.0.0, group: domain, api: v1, sdk: {name: heain-sdk-go, version: ">=1.0.0"}}
capabilities:
  - {name: caller.run, version: 1, formal: false, execution: job, ai: {used: false}}
uses:
  - {app: svc-app, capabilities: [svc.greet, svc.classify, id.check, ballot.cast]}
`

type env struct {
	f      *fake2
	svc    *App
	caller *App
	pki    *testpki.PKI
	base   string
}

func startEnv(t *testing.T) *env {
	t.Helper()
	p := testpki.New(t)
	_, _, corePair := p.Issue(t, "core", "G")
	f := &fake2{disco: map[string][]Instance{}}
	cs := httptest.NewUnstartedServer(http.HandlerFunc(f.h))
	cs.TLS = &tls.Config{Certificates: []tls.Certificate{corePair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: p.Pool()}
	cs.StartTLS()
	t.Cleanup(cs.Close)
	mk := func(name, cn, man string) *App {
		cert, key, _ := p.IssueApp(t, name, cn)
		mp := filepath.Join(t.TempDir(), "m.yaml")
		_ = os.WriteFile(mp, []byte(man), 0o644)
		a, err := Start(context.Background(), Options{ManifestPath: mp, InstanceID: strings.Split(cn, ".")[1],
			Core: core.Config{URL: cs.URL, NodeID: "G", CertFile: cert, KeyFile: key, CAFile: p.CAFile}, Logf: t.Logf})
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	e := &env{f: f, pki: p, svc: mk("svc", "svc-app.s1", svcManifest), caller: mk("caller", "caller-app.c1", callerManifest)}
	srv := e.svc.NewServer()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	ok := func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true,"trace":"` + TraceID(r.Context()) + `"}`))
	}
	must(srv.HandleFunc("POST /v1/greet", ok))
	must(srv.HandleFunc("GET /v1/greet/{id}", ok))
	must(srv.HandleFunc("POST /v1/classify", func(w http.ResponseWriter, r *http.Request) {
		c := 0.9
		if _, err := e.svc.Reason(r.Context(), Decision{Capability: "svc.classify", Input: []byte("raw secret input"), Decision: "cat",
			Confidence: &c, Summary: "looks like a cat", Factors: []Factor{{Name: "ears", Value: 0.9}}, Role: "decision"}); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		ok(w, r)
	}))
	must(srv.HandleFunc("POST /v1/classify-forgetful", ok))
	must(srv.HandleFunc("POST /v1/id", ok))
	must(srv.HandleFunc("POST /v1/ballot", ok))
	if err := srv.HandleFunc("POST /v1/undeclared", ok); err == nil {
		t.Fatal("an undeclared endpoint must be refused")
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx, l) }()
	e.base = "https://" + l.Addr().String()
	for _, c := range []string{"svc.greet", "svc.classify"} {
		f.disco[c] = []Instance{{AppID: "svc-app", InstanceID: "s1", EndpointBase: e.base, Execution: "direct"}}
	}
	f.disco["id.check"] = []Instance{{AppID: "svc-app", InstanceID: "s1", EndpointBase: e.base, Execution: "direct", Lane: "identity"}}
	f.disco["ballot.cast"] = []Instance{{AppID: "svc-app", InstanceID: "s1", EndpointBase: e.base, Execution: "direct", Lane: "ballot"}}
	time.Sleep(50 * time.Millisecond)
	return e
}

func TestFormalCallsAreAuditedExactlyOnce(t *testing.T) {
	e := startEnv(t)
	ctx := context.Background()
	if _, err := e.caller.Call(ctx, CallSpec{App: "svc-app", Capability: "svc.greet", Method: "POST", Path: "/v1/greet", Body: map[string]any{"x": 1}}); err != nil {
		t.Fatal(err)
	}
	if ev, _ := e.f.count(); ev != 1 {
		t.Fatalf("formal call: %d audit events, want 1", ev)
	}
	if _, err := e.caller.Call(ctx, CallSpec{App: "svc-app", Capability: "svc.greet", Method: "GET", Path: "/v1/greet/7"}); err != nil {
		t.Fatal(err)
	}
	if ev, _ := e.f.count(); ev != 1 {
		t.Fatalf("non-formal call must not be audited (%d events)", ev)
	}
	e.f.mu.Lock()
	got := e.f.events[0]
	e.f.mu.Unlock()
	if got["actor"] != "caller-app.c1" || got["capability"] != "svc.greet" || got["outcome"] != "ok" || got["trace_id"] == "" {
		t.Fatalf("event: %v", got)
	}
}

func TestAIRecordsAreRequiredAndLinked(t *testing.T) {
	e := startEnv(t)
	ctx := context.Background()
	if _, err := e.caller.Call(ctx, CallSpec{App: "svc-app", Capability: "svc.classify", Method: "POST", Path: "/v1/classify"}); err != nil {
		t.Fatal(err)
	}
	e.f.mu.Lock()
	rec, ev := e.f.records[0], e.f.events[0]
	e.f.mu.Unlock()
	raw, _ := json.Marshal(rec)
	if strings.Contains(string(raw), "raw secret input") {
		t.Fatal("the raw input must never be sent")
	}
	ids, _ := ev["detail"].(map[string]any)["reasoning_record_ids"].([]any)
	if len(ids) != 1 || ids[0] != rec["record_id"] || ev["trace_id"] != rec["trace_id"] {
		t.Fatalf("record not linked to its audit event: %v / %v", ev, rec)
	}
	var r Record
	_ = json.Unmarshal(raw, &r)
	if err := VerifyRecord(r, &e.svc.pair); err != nil {
		t.Fatalf("signature: %v", err)
	}
	_, err := e.caller.Call(ctx, CallSpec{App: "svc-app", Capability: "svc.classify", Method: "POST", Path: "/v1/classify-forgetful"})
	var ce *CallError
	if !errors.As(err, &ce) || ce.Code != "reasoning_record_missing" {
		t.Fatalf("an AI answer without its record must be refused, got %v", err)
	}
	if _, err := e.svc.Reason(ctx, Decision{Capability: "svc.greet"}); !errors.Is(err, ErrNotAI) {
		t.Fatalf("a non-AI capability cannot have records: %v", err)
	}
	if _, err := e.svc.Reason(ctx, Decision{Capability: "svc.classify", Role: "decision"}); err == nil {
		t.Fatal("role decision without factors must be refused")
	}
}

func TestLanes(t *testing.T) {
	e := startEnv(t)
	// a call without the lane header is refused (and audited as refused)
	cl, _ := e.caller.appClient("svc-app.s1")
	req, _ := http.NewRequest("POST", e.base+"/v1/id", nil)
	resp, err := cl.Do(req)
	if err != nil || resp.StatusCode != 400 {
		t.Fatalf("missing lane: %v %v", err, resp)
	}
	// the same trace id in identity then ballot: the second is refused
	for i, p := range []struct{ path, lane string }{{"/v1/id", "identity"}, {"/v1/ballot", "ballot"}} {
		req, _ := http.NewRequest("POST", e.base+p.path, nil)
		req.Header.Set(HeaderTrace, "trace-crossing")
		req.Header.Set(HeaderLane, p.lane)
		resp, err := cl.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if want := []int{200, 400}[i]; resp.StatusCode != want {
			t.Fatalf("%s: %d, want %d", p.path, resp.StatusCode, want)
		}
	}
	// through Call, a new trace id is used when the lane changes
	ctx := WithTrace(context.Background(), "", "identity")
	if _, err := e.caller.Call(ctx, CallSpec{App: "svc-app", Capability: "id.check", Method: "POST", Path: "/v1/id"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.caller.Call(ctx, CallSpec{App: "svc-app", Capability: "ballot.cast", Method: "POST", Path: "/v1/ballot"}); err != nil {
		t.Fatalf("Call must not carry an identity trace into the ballot lane: %v", err)
	}
}

func TestUsesAndCalleeIdentity(t *testing.T) {
	e := startEnv(t)
	ctx := context.Background()
	if _, err := e.svc.Call(ctx, CallSpec{App: "caller-app", Capability: "caller.run", Method: "POST", Path: "/x"}); !errors.Is(err, ErrNotDeclared) {
		t.Fatalf("undeclared dependency: %v", err)
	}
	// discovery says s1 lives at the address, but the client expects s2: refused
	e.f.mu.Lock()
	e.f.disco["svc.greet"] = []Instance{{AppID: "svc-app", InstanceID: "s2", EndpointBase: e.base, Execution: "direct"}}
	e.f.mu.Unlock()
	DiscoverTTL = 0
	defer func() { DiscoverTTL = 10 * time.Second }()
	if _, err := e.caller.Call(ctx, CallSpec{App: "svc-app", Capability: "svc.greet", Method: "POST", Path: "/v1/greet"}); err == nil || !strings.Contains(err.Error(), "expected app instance") {
		t.Fatalf("an impostor instance must be refused, got %v", err)
	}
}

func TestCanonical(t *testing.T) {
	got, _ := Canonical(map[string]any{"b": 1e21, "a": []any{0.000001, 1e-7, 10.5, "é\n"}, "A": true})
	want := `{"A":true,"a":[0.000001,1e-7,10.5,"é\n"],"b":1e+21}`
	if string(got) != want {
		t.Fatalf("got %s\nwant %s", got, want)
	}
}
