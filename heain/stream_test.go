package heain

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

// streamRelease is closed by the test once the caller has the first bytes;
// the handler waits for it, so the answer must reach the caller before the
// handler returns.
var streamRelease chan struct{}

func streamHandler(w http.ResponseWriter, r *http.Request) {
	StreamBody(w)
	in, _ := io.ReadAll(r.Body)
	w.Header().Set("X-Range", r.Header.Get("Range"))
	w.WriteHeader(http.StatusPartialContent)
	_, _ = w.Write(bytes.ToUpper(in))
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	if streamRelease != nil {
		<-streamRelease
	}
	_, _ = w.Write([]byte("|end"))
}

func TestStreamedCall(t *testing.T) {
	e := startEnv(t)
	streamRelease = make(chan struct{})
	defer func() { streamRelease = nil }()
	ctx := context.Background()
	s, err := e.caller.Stream(ctx, CallSpec{App: "svc-app", Capability: "svc.greet", Method: "POST", Path: "/v1/stream"},
		http.Header{"Range": {"bytes=5-"}}, strings.NewReader("hello stream"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.StatusCode != http.StatusPartialContent || s.Header.Get("X-Range") != "bytes=5-" || s.Instance.InstanceID != "s1" {
		t.Fatalf("status %d, range %q, instance %q", s.StatusCode, s.Header.Get("X-Range"), s.Instance.InstanceID)
	}
	first := make([]byte, len("HELLO STREAM"))
	if _, err := io.ReadFull(s.Body, first); err != nil || string(first) != "HELLO STREAM" {
		t.Fatalf("first bytes before the handler returned: %q %v", first, err)
	}
	close(streamRelease)
	rest, _ := io.ReadAll(s.Body)
	if string(rest) != "|end" {
		t.Fatalf("rest %q", rest)
	}
	if ev, _ := e.f.count(); ev != 1 {
		t.Fatalf("a streamed formal call: %d audit events, want 1", ev)
	}
	e.f.mu.Lock()
	d, _ := e.f.events[0]["detail"].(map[string]any)
	e.f.mu.Unlock()
	if d["streamed"] != true || d["status"] != float64(206) {
		t.Fatalf("event detail %v", d)
	}
	if _, err := e.caller.Stream(ctx, CallSpec{App: "svc-app", Capability: "svc.greet", Method: "GET", Path: "/v1/nothing"}, nil, nil); err == nil {
		t.Fatal("a 404 must come back as an error")
	}
}
