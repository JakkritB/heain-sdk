package jobclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestRegisterSendsCorrectPayload(t *testing.T) {
	var got Endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/register" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c := New(server.URL)
	ep := Endpoint{ModuleName: "heain-image", StrategyName: "heain-image", BaseURL: "http://heain-image:9000", Token: "secret"}

	if err := c.Register(context.Background(), ep); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if got != ep {
		t.Fatalf("server received %+v, want %+v", got, ep)
	}
}

func TestKeepRegisteredReregistersOnInterval(t *testing.T) {
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c := New(server.URL)
	ep := Endpoint{ModuleName: "m", StrategyName: "m", BaseURL: "http://m", Token: "t"}

	ctx, cancel := context.WithTimeout(context.Background(), 220*time.Millisecond)
	defer cancel()

	KeepRegistered(ctx, c, ep, 50*time.Millisecond, nil)

	if got := atomic.LoadInt32(&calls); got < 3 {
		t.Fatalf("expected at least 3 registration calls in ~220ms at a 50ms interval, got %d", got)
	}
}
