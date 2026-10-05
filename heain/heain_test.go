package heain

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/heainframework/heain-sdk/core"
	"github.com/heainframework/heain-sdk/internal/testpki"
)

type fakeCore struct {
	calls      atomic.Int64
	heartbeats atomic.Int64
	gone       atomic.Bool
	lastCN     atomic.Value
}

func (f *fakeCore) handler(w http.ResponseWriter, r *http.Request) {
	f.calls.Add(1)
	if len(r.TLS.PeerCertificates) > 0 {
		f.lastCN.Store(r.TLS.PeerCertificates[0].Subject.CommonName)
	}
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/v1/app/info":
		_, _ = w.Write([]byte(`{"core_version":"1.3.0","api_versions":["v1"],"node_id":"G","tier":"ZONE","mode":"normal","unknown_new_field":1}`))
	case "/v1/app/register":
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["instance_id"] != "a1" {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":{"code":"manifest_invalid","message":"x","retryable":false}}`))
			return
		}
		_, _ = w.Write([]byte(`{"registration_id":"hello-app.a1","status":"active","heartbeat_interval_s":1,"ttl_s":3}`))
	case "/v1/app/heartbeat":
		f.heartbeats.Add(1)
		_, _ = w.Write([]byte(`{"registration_id":"hello-app.a1","status":"active"}`))
	case "/v1/app/deregister":
		f.gone.Store(true)
		_, _ = w.Write([]byte(`{"status":"deregistered"}`))
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, cn string) (*fakeCore, core.Config) {
	t.Helper()
	p := testpki.New(t)
	_, _, srvPair := p.Issue(t, "core", "G")
	cert, key, _ := p.Issue(t, "app", cn)
	f := &fakeCore{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(f.handler))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{srvPair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: p.Pool(), MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return f, core.Config{URL: srv.URL, NodeID: "G", CertFile: cert, KeyFile: key, CAFile: p.CAFile, Timeout: 5 * time.Second}
}

func writeManifest(t *testing.T, body string) string {
	p := filepath.Join(t.TempDir(), "heain-app.yaml")
	_ = os.WriteFile(p, []byte(body), 0o644)
	return p
}

const good = `manifest_version: 1
app: {id: hello-app, version: 1.0.0, group: domain, api: v1, sdk: {name: heain-sdk-go, version: ">=1.0.0 <2.0.0"}}
capabilities:
  - {name: hello.greet, version: 1, formal: true, execution: direct, ai: {used: false}}
endpoints:
  - {method: POST, path: /v1/greet, capability: hello.greet, formal: true}
`

func TestStartRegistersHeartbeatsAndLeaves(t *testing.T) {
	f, cfg := setup(t, "hello-app.a1")
	app, err := Start(context.Background(), Options{ManifestPath: writeManifest(t, good), InstanceID: "a1", Core: cfg, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	if app.Status() != "active" || f.lastCN.Load() != "hello-app.a1" {
		t.Fatalf("status %s, cn %v", app.Status(), f.lastCN.Load())
	}
	time.Sleep(2500 * time.Millisecond)
	if f.heartbeats.Load() < 2 {
		t.Fatalf("heartbeats %d, want >= 2 at the core's 1 s interval", f.heartbeats.Load())
	}
	if err := app.Close(context.Background()); err != nil || !f.gone.Load() {
		t.Fatalf("close: %v, deregistered %v", err, f.gone.Load())
	}
}

func TestInvalidManifestNeverStarts(t *testing.T) {
	f, cfg := setup(t, "hello-app.a1")
	bad := strings.Replace(good, "formal: true, execution", "execution", 1)
	_, err := Start(context.Background(), Options{ManifestPath: writeManifest(t, bad), InstanceID: "a1", Core: cfg})
	if err == nil || !strings.Contains(err.Error(), "manifest_formal_missing") {
		t.Fatalf("want manifest_formal_missing, got %v", err)
	}
	if f.calls.Load() != 0 {
		t.Fatalf("an invalid manifest must not reach the core (%d calls)", f.calls.Load())
	}
}

func TestWrongIdentityNeverStarts(t *testing.T) {
	f, cfg := setup(t, "other-app.a1")
	_, err := Start(context.Background(), Options{ManifestPath: writeManifest(t, good), InstanceID: "a1", Core: cfg})
	if !errors.Is(err, ErrIdentity) || f.calls.Load() != 0 {
		t.Fatalf("want identity_mismatch before any call, got %v (%d calls)", err, f.calls.Load())
	}
}

func TestCoreMustPresentItsNodeID(t *testing.T) {
	_, cfg := setup(t, "hello-app.a1")
	cfg.NodeID = "Z" // the server certificate is for G
	_, err := Start(context.Background(), Options{ManifestPath: writeManifest(t, good), InstanceID: "a1", Core: cfg})
	if err == nil || !strings.Contains(err.Error(), "core unreachable") {
		t.Fatalf("a core that is not the expected node must be refused, got %v", err)
	}
}
