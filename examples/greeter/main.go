// Command greeter is the heain-sdk example server: formal and non-formal
// endpoints, an AI capability that writes reasoning records, and two
// unlinkable lanes. The SDK does the audit, lane and record rules; the
// handlers only do the work.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/heainframework/heain-sdk/examples/internal/cli"
	"github.com/heainframework/heain-sdk/heain"
)

func main() {
	f := cli.Register("heain-app.yaml")
	listen := flag.String("listen", "127.0.0.1:19443", "address for the app's mTLS endpoints")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	l, err := net.Listen("tcp", *listen)
	if err != nil {
		cli.Fail("listen", err)
	}
	app := f.Start(ctx, "https://"+l.Addr().String())
	srv := app.NewServer()
	reply := func(w http.ResponseWriter, r *http.Request, v map[string]any) {
		v["trace"] = heain.TraceID(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	type input struct {
		Name string `json:"name"`
		Text string `json:"text"`
	}
	decode := func(r *http.Request) (in input) { _ = json.NewDecoder(r.Body).Decode(&in); return }
	handlers := map[string]http.HandlerFunc{
		"POST /v1/hello": func(w http.ResponseWriter, r *http.Request) {
			in := decode(r)
			reply(w, r, map[string]any{"greeting": "hello " + in.Name, "by": heain.Caller(r.Context())})
		},
		"GET /v1/hello/{name}": func(w http.ResponseWriter, r *http.Request) {
			reply(w, r, map[string]any{"greeting": "hi " + r.PathValue("name")})
		},
		"POST /v1/tone": func(w http.ResponseWriter, r *http.Request) {
			in := decode(r)
			tone, conf, why := classify(in.Text)
			id, err := app.Reason(r.Context(), heain.Decision{Capability: "greet.tone", Input: []byte(in.Text), Decision: tone,
				Confidence: &conf, Summary: why, Role: "decision", Factors: []heain.Factor{{Name: "exclamations", Value: float64(strings.Count(in.Text, "!"))}}})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			reply(w, r, map[string]any{"tone": tone, "record_id": id})
		},
		"POST /v1/tone-unrecorded": func(w http.ResponseWriter, r *http.Request) {
			in := decode(r)
			tone, _, _ := classify(in.Text)
			reply(w, r, map[string]any{"tone": tone})
		},
		"POST /v1/id":     func(w http.ResponseWriter, r *http.Request) { reply(w, r, map[string]any{"verified": true}) },
		"POST /v1/ballot": func(w http.ResponseWriter, r *http.Request) { reply(w, r, map[string]any{"cast": true}) },
	}
	for pat, h := range handlers {
		if err := srv.HandleFunc(pat, h); err != nil {
			cli.Fail("handle", err)
		}
	}
	fmt.Printf("SERVING %s\n", l.Addr())
	if err := srv.Serve(ctx, l); err != nil && ctx.Err() == nil {
		cli.Fail("serve", err)
	}
	if err := app.Close(context.Background()); err != nil {
		cli.Fail("close", err)
	}
	fmt.Println("DEREGISTERED")
}

// classify is a tiny rule "model": loud or calm.
func classify(text string) (string, float64, string) {
	if n := strings.Count(text, "!"); n >= 2 {
		return "loud", 0.9, fmt.Sprintf("%d exclamation marks", n)
	}
	return "calm", 0.7, "fewer than 2 exclamation marks"
}
