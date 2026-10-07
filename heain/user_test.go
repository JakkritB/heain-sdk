package heain

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
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

const pubManifest = `manifest_version: 1
app: {id: svc-app, version: 1.0.0, group: domain, api: v1, sdk: {name: heain-sdk-go, version: ">=1.0.0"}}
capabilities:
  - {name: svc.items, version: 1, formal: true, execution: direct, ai: {used: false}}
endpoints:
  - {method: POST, path: /v1/items, capability: svc.items, formal: true, public: true}
  - {method: GET, path: "/v1/items/{id}", capability: svc.items, formal: false, public: true}
  - {method: POST, path: /v1/admin-only, capability: svc.items, formal: true}
`

const gwManifest = `manifest_version: 1
app: {id: gw-app, version: 1.0.0, group: base, api: v1, sdk: {name: heain-sdk-go, version: ">=1.0.0"}}
capabilities:
  - {name: gw.proxy, version: 1, formal: false, execution: job, ai: {used: false}}
`

type fakeGW struct {
	mu     sync.Mutex
	events []map[string]any
}

func (f *fakeGW) h(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	switch {
	case r.URL.Path == "/v1/app/info":
		_, _ = w.Write([]byte(`{"core_version":"1.3.0","api_versions":["v1"],"node_id":"G","user_assertion_issuers":["gw-app"]}`))
	case r.URL.Path == "/v1/app/register":
		_, _ = w.Write([]byte(`{"registration_id":"x","status":"active","heartbeat_interval_s":30}`))
	case r.URL.Path == "/v1/app/audit/events":
		f.mu.Lock()
		f.events = append(f.events, body)
		f.mu.Unlock()
		w.WriteHeader(202)
	case strings.HasPrefix(r.URL.Path, "/v1/app/certs/"):
		_, _ = w.Write([]byte(`{"valid":true}`))
	case r.URL.Path == "/v1/app/gateway/routes":
		_, _ = w.Write([]byte(`{"config_version":7,"routes":[{"app":"svc-app","method":"POST","path":"/v1/items","roles":["clerk"],"auth":"user","status":"ok","instances":[{"instance_id":"s1","app_version":"1.0.0","endpoint_base":"https://x"}]}]}`))
	default:
		_, _ = w.Write([]byte(`{}`))
	}
}

type gwEnv struct {
	f              *fakeGW
	svc, g1, g2, o *App
	g1cert         *x509.Certificate
	base           string
}

func startGW(t *testing.T) *gwEnv {
	t.Helper()
	p := testpki.New(t)
	_, _, corePair := p.Issue(t, "core", "G")
	f := &fakeGW{}
	cs := httptest.NewUnstartedServer(http.HandlerFunc(f.h))
	cs.TLS = &tls.Config{Certificates: []tls.Certificate{corePair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: p.Pool()}
	cs.StartTLS()
	t.Cleanup(cs.Close)
	e := &gwEnv{f: f}
	mk := func(name, cn, man string) *App {
		cert, key, pair := p.IssueApp(t, name, cn)
		if cn == "gw-app.g1" {
			e.g1cert, _ = x509.ParseCertificate(pair.Certificate[0])
		}
		mp := filepath.Join(t.TempDir(), "m.yaml")
		_ = os.WriteFile(mp, []byte(man), 0o644)
		a, err := Start(context.Background(), Options{ManifestPath: mp, InstanceID: strings.Split(cn, ".")[1],
			Core: core.Config{URL: cs.URL, NodeID: "G", CertFile: cert, KeyFile: key, CAFile: p.CAFile}, Logf: t.Logf})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = a.Close(context.Background()) })
		return a
	}
	e.svc = mk("svc", "svc-app.s1", pubManifest)
	e.g1 = mk("g1", "gw-app.g1", gwManifest)
	e.g2 = mk("g2", "gw-app.g2", gwManifest)
	e.o = mk("o", "other-app.o1", strings.ReplaceAll(gwManifest, "gw-app", "other-app"))
	srv := e.svc.NewServer()
	h := func(w http.ResponseWriter, r *http.Request) {
		u := UserOf(r.Context())
		if u == nil {
			_, _ = w.Write([]byte(`{"user":null}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"user": u.ID, "roles": u.Roles, "gateway": u.Gateway, "clerk": u.HasRole("clerk")})
	}
	for _, pat := range []string{"POST /v1/items", "GET /v1/items/{id}", "POST /v1/admin-only"} {
		if err := srv.HandleFunc(pat, h); err != nil {
			t.Fatal(err)
		}
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx, l) }()
	e.base = "https://" + l.Addr().String()
	time.Sleep(50 * time.Millisecond)
	return e
}

// send makes a call from app `from` with assertion hdr ("" = none).
func (e *gwEnv) send(t *testing.T, from *App, method, path, trace, hdr string) (int, string) {
	t.Helper()
	cl, err := from.AppClient("svc-app", "s1")
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(method, e.base+path, strings.NewReader(`{}`))
	req.Header.Set(HeaderTrace, trace)
	if hdr != "" {
		req.Header.Set(HeaderUser, hdr)
	}
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func assertion(t *testing.T, a *App, aud, method, path, trace string) string {
	t.Helper()
	h, err := a.SignUserAssertion(UserAssertion{Audience: aud, Method: method, Path: path, Trace: trace, Subject: "u-17", Name: "Somchai",
		Roles: []string{"clerk"}, AuthMethod: "password+totp", Session: "sess-1"})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestUserAssertions(t *testing.T) {
	e := startGW(t)
	// a person through the gateway
	h := assertion(t, e.g1, "svc-app", "POST", "/v1/items", "tr-1")
	code, body := e.send(t, e.g1, "POST", "/v1/items", "tr-1", h)
	if code != 200 || !strings.Contains(body, `"user":"u-17"`) || !strings.Contains(body, `"gateway":"gw-app.g1"`) || !strings.Contains(body, `"clerk":true`) {
		t.Fatalf("person: %d %s", code, body)
	}
	e.f.mu.Lock()
	ev := e.f.events[len(e.f.events)-1]
	e.f.mu.Unlock()
	d := ev["detail"].(map[string]any)
	if ev["outcome"] != "ok" || d["user"] != "u-17" || d["user_assertion"] != h || ev["actor"] != "gw-app.g1" {
		t.Fatalf("audit: %v", ev)
	}
	// the recorded assertion still proves who acted
	u, _ := ParseUserAssertion(d["user_assertion"].(string))
	if VerifyUserAssertion(u, e.g1cert) != nil || u.Subject != "u-17" || u.Issuer != "gw-app.g1" {
		t.Fatal("recorded assertion does not verify")
	}
	u.Subject = "u-18"
	if VerifyUserAssertion(u, e.g1cert) == nil {
		t.Fatal("a changed assertion must not verify")
	}
	// replay
	if code, _ := e.send(t, e.g1, "POST", "/v1/items", "tr-1", h); code != 401 {
		t.Fatalf("replay: %d", code)
	}
	// no assertion: an app call (or an anonymous route), no person
	if code, body := e.send(t, e.g1, "GET", "/v1/items/3", "tr-2", ""); code != 200 || !strings.Contains(body, `"user":null`) {
		t.Fatalf("no assertion: %d %s", code, body)
	}
	for name, c := range map[string]struct {
		from                *App
		method, path, trace string
		amethod, apath, aud string
		signer              *App
	}{
		"other path":         {e.g1, "POST", "/v1/items", "t-a", "GET", "/v1/items/3", "svc-app", e.g1},
		"other app":          {e.g1, "POST", "/v1/items", "t-b", "POST", "/v1/items", "x-app", e.g1},
		"other trace":        {e.g1, "POST", "/v1/items", "t-c", "POST", "/v1/items", "svc-app", e.g1},
		"not public":         {e.g1, "POST", "/v1/admin-only", "t-d", "POST", "/v1/admin-only", "svc-app", e.g1},
		"not a gateway":      {e.o, "POST", "/v1/items", "t-e", "POST", "/v1/items", "svc-app", e.o},
		"another instance's": {e.g1, "POST", "/v1/items", "t-f", "POST", "/v1/items", "svc-app", e.g2},
	} {
		tr := c.trace
		if name == "other trace" {
			tr = "t-zz"
		}
		hdr := assertion(t, c.signer, c.aud, c.amethod, c.apath, tr)
		if code, body := e.send(t, c.from, c.method, c.path, c.trace, hdr); code != 401 || !strings.Contains(body, "user_assertion_invalid") {
			t.Errorf("%s: %d %s", name, code, body)
		}
	}
	// refusals of formal endpoints are audited
	e.f.mu.Lock()
	refused := 0
	for _, ev := range e.f.events {
		if ev["outcome"] == "refused:user_assertion_invalid" {
			refused++
		}
	}
	e.f.mu.Unlock()
	if refused < 5 {
		t.Fatalf("refusals audited: %d", refused)
	}
	if _, err := e.g1.SignUserAssertion(UserAssertion{Audience: "svc-app"}); err == nil {
		t.Fatal("an incomplete assertion must not be signed")
	}
	routes, ver, err := e.g1.GatewayRoutes(context.Background())
	if err != nil || ver != 7 || len(routes) != 1 || routes[0].Instances[0].InstanceID != "s1" || routes[0].Roles[0] != "clerk" {
		t.Fatalf("routes: %v %d %v", routes, ver, err)
	}
}
