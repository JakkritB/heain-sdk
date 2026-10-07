package heain

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

func TestModelFromTheRegistry(t *testing.T) {
	p := testpki.New(t)
	_, _, corePair := p.Issue(t, "core", "G")
	var mu sync.Mutex
	bases := map[string]string{}
	var lastBroadcastQuery string
	cs := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/app/info":
			_, _ = w.Write([]byte(`{"core_version":"1.3.0","api_versions":["v1"],"node_id":"G"}`))
		case r.URL.Path == "/v1/app/register":
			_, _ = w.Write([]byte(`{"registration_id":"x","status":"active","heartbeat_interval_s":30}`))
		case r.URL.Path == "/v1/app/audit/events":
			w.WriteHeader(202)
		case strings.HasPrefix(r.URL.Path, "/v1/app/certs/"):
			_, _ = w.Write([]byte(`{"valid":true}`))
		case r.URL.Path == "/v1/app/discover":
			mu.Lock()
			defer mu.Unlock()
			app, inst := "heain-model", "m1"
			if r.URL.Query().Get("capability") == "files.read" {
				app, inst = "heain-files", "f1"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"instances": []map[string]any{{"app_id": app, "instance_id": inst, "endpoint_base": bases[app], "execution": "direct"}}})
		case r.URL.Path == "/v1/app/broadcasts":
			mu.Lock()
			lastBroadcastQuery = r.URL.RawQuery
			mu.Unlock()
			_, _ = w.Write([]byte(`{"broadcasts":[{"seq":7,"discovery_id":"demo-app-card","form":"RAW","payload":{"model":"asr"}}],"last_seq":9}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	cs.TLS = &tls.Config{Certificates: []tls.Certificate{corePair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: p.Pool()}
	cs.StartTLS()
	t.Cleanup(cs.Close)
	mk := func(name, cn, man string) *App {
		cert, key, _ := p.IssueApp(t, name, cn)
		mp := filepath.Join(t.TempDir(), "m.yaml")
		_ = os.WriteFile(mp, []byte(man), 0o644)
		a, err := Start(context.Background(), Options{ManifestPath: mp, InstanceID: strings.Split(cn, ".")[1], StateDir: t.TempDir(),
			Core: core.Config{URL: cs.URL, NodeID: "G", CertFile: cert, KeyFile: key, CAFile: p.CAFile}, Logf: t.Logf})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = a.Close(context.Background()) })
		return a
	}
	hdr := `manifest_version: 1
app: {id: %s, version: 1.0.0, group: base, api: v1, sdk: {name: heain-sdk-go, version: ">=1.0.0"}}
`
	model := mk("model", "heain-model.m1", strings.Replace(hdr, "%s", "heain-model", 1)+`capabilities:
  - {name: model.resolve, version: 1, formal: false, execution: direct, ai: {used: false}}
endpoints:
  - {method: POST, path: /v1/resolve, capability: model.resolve, formal: false}
`)
	files := mk("files", "heain-files.f1", strings.Replace(hdr, "%s", "heain-files", 1)+`capabilities:
  - {name: files.read, version: 1, formal: false, execution: direct, ai: {used: false}}
endpoints:
  - {method: GET, path: "/v1/files/{id}/chunks/{n}", capability: files.read, formal: false}
`)
	user := mk("user", "demo-app.d1", strings.Replace(hdr, "%s", "demo-app", 1)+`capabilities:
  - {name: demo.run, version: 1, formal: false, execution: job, ai: {used: false}}
uses:
  - {app: heain-model, capabilities: [model.resolve]}
  - {app: heain-files, capabilities: [files.read]}
`)
	weights := []byte(strings.Repeat("weights-", 3000))
	sum := sha256.Sum256(weights)
	good := hex.EncodeToString(sum[:])
	var mmu sync.Mutex
	answer := map[string]any{"model": "asr", "version": "3", "state": "production", "sha256": good, "size": len(weights), "runtime": "onnx", "file": "fid-1"}
	chunkGets := 0
	serve := func(a *App, pat string, h http.HandlerFunc) string {
		srv := a.NewServer()
		if err := srv.HandleFunc(pat, h); err != nil {
			t.Fatal(err)
		}
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		go func() { _ = srv.Serve(ctx, l) }()
		return "https://" + l.Addr().String()
	}
	mu.Lock()
	bases["heain-model"] = serve(model, "POST /v1/resolve", func(w http.ResponseWriter, r *http.Request) {
		mmu.Lock()
		defer mmu.Unlock()
		if Caller(r.Context()) != "demo-app.d1" {
			http.Error(w, "who", 403)
			return
		}
		_ = json.NewEncoder(w).Encode(answer)
	})
	bases["heain-files"] = serve(files, "GET /v1/files/{id}/chunks/{n}", func(w http.ResponseWriter, r *http.Request) {
		mmu.Lock()
		chunkGets++
		mmu.Unlock()
		n := map[string]int{"0": 0, "1": 1, "2": 2}[r.PathValue("n")]
		part := weights[n*10000 : min((n+1)*10000, len(weights))]
		_ = json.NewEncoder(w).Encode(map[string]any{"n": n, "last": (n+1)*10000 >= len(weights), "data_b64": base64.StdEncoding.EncodeToString(part)})
	})
	mu.Unlock()
	time.Sleep(50 * time.Millisecond)

	dir := t.TempDir()
	art, err := user.Model(context.Background(), "asr", dir)
	if err != nil {
		t.Fatal(err)
	}
	if art.SHA256 != good || art.Version != "3" || art.State != "production" {
		t.Fatalf("artifact: %+v", art)
	}
	if b, _ := os.ReadFile(art.Path); string(b) != string(weights) {
		t.Fatal("content")
	}
	if chunkGets != 3 {
		t.Fatalf("chunks fetched: %d", chunkGets)
	}
	// a verified copy is reused
	if _, err := user.Model(context.Background(), "asr", dir); err != nil || chunkGets != 3 {
		t.Fatalf("cache: %v %d", err, chunkGets)
	}
	// a registry hash that the bytes do not match: refused, nothing kept
	mmu.Lock()
	answer["version"], answer["sha256"] = "4", strings.Repeat("ab", 32)
	mmu.Unlock()
	if _, err := user.Model(context.Background(), "asr", dir); err == nil || !strings.Contains(err.Error(), "does not match the registry") {
		t.Fatalf("mismatch: %v", err)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("a bad download was kept: %d files", len(ents))
	}
	// an app that does not declare heain-model cannot ask
	if _, err := files.ResolveModel(context.Background(), "asr"); err == nil {
		t.Fatal("undeclared use")
	}
	// broadcasts
	got, last, err := user.Broadcasts(context.Background(), 5, 10)
	if err != nil || len(got) != 1 || got[0].Seq != 7 || last != 9 || lastBroadcastQuery != "after=5&limit=10" {
		t.Fatalf("broadcasts: %+v %d %v %q", got, last, err, lastBroadcastQuery)
	}
}
