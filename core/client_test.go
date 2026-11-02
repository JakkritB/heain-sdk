package core

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
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

// heain-core C13: 503 cert_unverifiable is ErrCertUnverifiable with its
// Retry-After; SetCertUnverifiableRetries sends the call again after it.
func TestCertUnverifiable(t *testing.T) {
	p := testpki.New(t)
	_, _, srvPair := p.Issue(t, "core", "G")
	cert, key, _ := p.Issue(t, "app", "hello-app.a1")
	var n atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if n.Add(1)%2 == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(503)
			_, _ = w.Write([]byte(`{"error":{"code":"cert_unverifiable","message":"cannot check now","retryable":true}}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"active"}`))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{srvPair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: p.Pool()}
	srv.StartTLS()
	defer srv.Close()
	c, err := New(Config{URL: srv.URL, NodeID: "G", CertFile: cert, KeyFile: key, CAFile: p.CAFile, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Do(context.Background(), "POST", "/v1/app/heartbeat", nil, map[string]any{}, nil)
	var e *Error
	if !errors.Is(err, ErrCertUnverifiable) || !errors.As(err, &e) || e.RetryAfter != time.Second || !e.Retryable || e.Status != 503 {
		t.Fatalf("no retries: %v", err)
	}
	c.SetCertUnverifiableRetries(2)
	n.Store(0)
	s := time.Now()
	if _, err := c.Do(context.Background(), "POST", "/v1/app/heartbeat", nil, map[string]any{"x": 1}, nil); err != nil || time.Since(s) < time.Second {
		t.Fatalf("with retries: %v after %v", err, time.Since(s))
	}
	if errors.Is(&Error{Code: "not_registered"}, ErrCertUnverifiable) {
		t.Fatal("another code must not match")
	}
}
