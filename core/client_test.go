package core

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/heainframework/heain-sdk/internal/testpki"
)

func TestErrorsAndTLS13(t *testing.T) {
	p := testpki.New(t)
	_, _, srvPair := p.Issue(t, "core", "G")
	cert, key, _ := p.Issue(t, "app", "hello-app.a1")
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS.Version != tls.VersionTLS13 {
			t.Errorf("TLS version %x", r.TLS.Version)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(403)
		_, _ = w.Write([]byte(`{"error":{"code":"not_registered","message":"register first","retryable":false}}`))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{srvPair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: p.Pool()}
	srv.StartTLS()
	defer srv.Close()
	c, err := New(Config{URL: srv.URL, NodeID: "G", CertFile: cert, KeyFile: key, CAFile: p.CAFile, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Heartbeat(context.Background())
	if !IsCode(err, "not_registered") {
		t.Fatalf("want not_registered, got %v", err)
	}
}
