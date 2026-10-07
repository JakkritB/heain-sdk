package heain

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/heainframework/heain-sdk/core"
	"github.com/heainframework/heain-sdk/internal/testpki"
)

const subjManifest = `manifest_version: 1
app: {id: crm-app, version: 1.0.0, group: domain, api: v1, sdk: {name: heain-sdk-go, version: ">=1.0.0"}}
capabilities:
  - {name: subject.rights, version: 1, formal: true, execution: direct, ai: {used: false}}
endpoints:
  - {method: POST, path: /v1/subject-rights/export, capability: subject.rights, formal: true}
  - {method: POST, path: /v1/subject-rights/erase, capability: subject.rights, formal: true}
`

func TestNormalizeIdentifier(t *testing.T) {
	for _, c := range [][3]string{
		{IdentEmail, " Somchai@Example.TEST ", "somchai@example.test"},
		{IdentPhone, "+66 81-234 5678", "+66812345678"},
		{IdentPhone, "081 234 5678", "0812345678"},
		{IdentGatewayUser, " somchai ", "somchai"},
	} {
		if got := NormalizeIdentifier(c[0], c[1]); got != c[2] {
			t.Fatalf("%s %q: %q", c[0], c[1], got)
		}
	}
	r := SubjectRequest{Identifiers: []SubjectIdentifier{{IdentEmail, "A@B.test"}, {IdentPhone, "+66 81 000"}, {IdentEmail, "c@d.test"}}}
	if !r.Has(IdentEmail, "a@b.TEST") || !r.Has(IdentPhone, "+6681000") || r.Has(IdentEmail, "x@y.test") || r.Has(IdentGatewayUser, "") {
		t.Fatal("Has")
	}
	if v := r.Values(IdentEmail); len(v) != 2 || v[0] != "a@b.test" {
		t.Fatalf("Values: %v", v)
	}
}

func TestSubjectRights(t *testing.T) {
	p := testpki.New(t)
	_, _, corePair := p.Issue(t, "core", "G")
	f := &fakeGW{}
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
		t.Cleanup(func() { _ = a.Close(context.Background()) })
		return a
	}
	crm := mk("crm", "crm-app.c1", subjManifest)
	consent := mk("consent", "heain-consent.k1", strings.ReplaceAll(gwManifest, "gw-app", "heain-consent"))
	other := mk("other", "other-app.o1", strings.ReplaceAll(gwManifest, "gw-app", "other-app"))

	var got []SubjectRequest
	srv := crm.NewServer()
	if err := srv.HandleSubjectRights(SubjectRights{}); err == nil {
		t.Fatal("an empty implementation must be refused")
	}
	if err := srv.HandleSubjectRights(SubjectRights{
		Export: func(_ context.Context, r SubjectRequest) (SubjectExport, error) {
			got = append(got, r)
			if !r.Has(IdentEmail, "somchai@example.test") {
				return SubjectExport{}, nil
			}
			return SubjectExport{Items: []SubjectItem{{Kind: "customer", ID: "c-1", Data: map[string]any{"name": "Somchai"}}}}, nil
		},
		Erase: func(_ context.Context, r SubjectRequest) (SubjectErasure, error) {
			got = append(got, r)
			return SubjectErasure{Erased: []SubjectItem{{Kind: "customer", ID: "c-1", Data: "LEAK"}},
				Held: []SubjectItem{{Kind: "invoice", ID: "inv-9", Reason: "retention_min", Until: time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)}}}, nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx, l) }()
	base := "https://" + l.Addr().String()
	time.Sleep(50 * time.Millisecond)
	send := func(from *App, path, body string) (int, string) {
		cl, err := from.AppClient("crm-app", "c1")
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest("POST", base+path, strings.NewReader(body))
		req.Header.Set(HeaderTrace, NewID())
		resp, err := cl.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	q := `{"request":"r-1","subject":"s-1","identifiers":[{"kind":"email","value":"Somchai@Example.test"},{"kind":"heain-access:subject","value":"A-7"}]}`
	if c, b := send(consent, SubjectRightsExportPath, q); c != 200 || !strings.Contains(b, `"name":"Somchai"`) {
		t.Fatalf("export: %d %s", c, b)
	}
	if c, b := send(consent, SubjectRightsErasePath, strings.Replace(q, `"request"`, `"dry_run":true,"request"`, 1)); c != 200 ||
		strings.Contains(b, "LEAK") || !strings.Contains(b, `"reason":"retention_min"`) || !strings.Contains(b, `"until":"2031-01-01T00:00:00Z"`) {
		t.Fatalf("erase: %d %s", c, b)
	}
	if len(got) != 2 || !got[1].DryRun || got[0].Subject != "s-1" {
		t.Fatalf("requests: %+v", got)
	}
	for name, c := range map[string]struct {
		from *App
		path string
		body string
		want int
	}{
		"another app":       {other, SubjectRightsExportPath, q, 403},
		"no identifiers":    {consent, SubjectRightsExportPath, `{"request":"r","subject":"s","identifiers":[]}`, 400},
		"bad kind":          {consent, SubjectRightsExportPath, `{"request":"r","subject":"s","identifiers":[{"kind":"E MAIL","value":"x"}]}`, 400},
		"unknown field":     {consent, SubjectRightsExportPath, `{"request":"r","subject":"s","identifiers":[{"kind":"email","value":"x"}],"x":1}`, 400},
		"dry run on export": {consent, SubjectRightsExportPath, strings.Replace(q, `"request"`, `"dry_run":true,"request"`, 1), 400},
		"no request id":     {consent, SubjectRightsErasePath, strings.Replace(q, `"r-1"`, `""`, 1), 400},
	} {
		if code, b := send(c.from, c.path, c.body); code != c.want {
			t.Fatalf("%s: %d %s", name, code, b)
		}
	}
	if len(got) != 2 {
		t.Fatalf("a refused request reached the app: %d", len(got))
	}
}
