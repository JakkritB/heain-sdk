// Command refapp is the heain-sdk reference app for the conformance suite
// (spec 05). It is configured only through the container contract
// (heain.StartFromEnv) and uses every App API feature the suite checks:
// formal and non-formal endpoints, an AI capability with reasoning records,
// two unlinkable lanes, job capabilities (one with AI), P5, P7, an
// app-to-app call through discovery, offline rules and the journal.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/heainframework/heain-sdk/heain"
)

// modelSHA256 identifies the rule "model" (spec 04: the record carries a model hash).
var modelSHA256 = func() string {
	h := sha256.Sum256([]byte("ref-rules v1: loud if >= 2 '!'"))
	return hex.EncodeToString(h[:])
}()

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	app, err := heain.StartFromEnv(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "REFUSED: %v\n", err)
		os.Exit(2)
	}
	reply := func(w http.ResponseWriter, r *http.Request, v map[string]any) {
		v["trace"] = heain.TraceID(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	body := func(r *http.Request) map[string]any {
		m := map[string]any{}
		_ = json.NewDecoder(r.Body).Decode(&m)
		return m
	}
	str := func(m map[string]any, k string) string { s, _ := m[k].(string); return s }
	fail := func(w http.ResponseWriter, err error) { http.Error(w, err.Error(), http.StatusBadGateway) }

	srv := app.NewServer()
	h := map[string]http.HandlerFunc{
		"POST /v1/greet": func(w http.ResponseWriter, r *http.Request) {
			name := str(body(r), "name")
			if app.CurrentMode().Standalone() {
				// a domain event for the offline journal (spec 02 §9)
				if _, err := app.Journal(r.Context(), "greet.served", "", map[string]any{"standalone": true}); err != nil {
					fail(w, err)
					return
				}
			}
			reply(w, r, map[string]any{"greeting": "hello " + name, "by": heain.Caller(r.Context())})
		},
		"GET /v1/greet/{name}": func(w http.ResponseWriter, r *http.Request) {
			reply(w, r, map[string]any{"greeting": "hi " + r.PathValue("name")})
		},
		"POST /v1/score": func(w http.ResponseWriter, r *http.Request) {
			text := str(body(r), "text")
			tone, conf := rate(text)
			id, err := app.Reason(r.Context(), heain.Decision{Capability: "ref.score", Input: []byte(text), Decision: tone, Confidence: &conf,
				Summary: "counted exclamation marks", Role: "decision", ModelSHA256: modelSHA256,
				Factors: []heain.Factor{{Name: "exclamations", Value: float64(strings.Count(text, "!"))}}})
			if err != nil {
				fail(w, err)
				return
			}
			reply(w, r, map[string]any{"tone": tone, "record_id": id})
		},
		"POST /v1/id":     func(w http.ResponseWriter, r *http.Request) { reply(w, r, map[string]any{"verified": true}) },
		"POST /v1/ballot": func(w http.ResponseWriter, r *http.Request) { reply(w, r, map[string]any{"cast": true}) },
		"POST /v1/propose": func(w http.ResponseWriter, r *http.Request) {
			res, err := app.Propose(r.Context(), heain.Proposal{Type: "ref.grant.extend", Category: heain.CategoryAllowlist, Data: map[string]any{"grant": "g1"}})
			if err != nil {
				fail(w, err)
				return
			}
			reply(w, r, map[string]any{"action_id": res.ActionID, "result": res.Result})
		},
		"GET /v1/propose/{id}": func(w http.ResponseWriter, r *http.Request) {
			res, err := app.PolicyStatus(r.Context(), r.PathValue("id"))
			if err != nil {
				fail(w, err)
				return
			}
			reply(w, r, map[string]any{"action_id": res.ActionID, "result": res.Result})
		},
		"POST /v1/broadcast": func(w http.ResponseWriter, r *http.Request) {
			res, err := app.Broadcast(r.Context(), heain.NewID()[:8], "zone-a", map[string]any{"rule": "ref-lighting-adjust", "customer_id": "cust-42"})
			if err != nil {
				fail(w, err)
				return
			}
			reply(w, r, map[string]any{"action_id": res.ActionID, "result": res.Result})
		},
		"POST /v1/relay": func(w http.ResponseWriter, r *http.Request) {
			var out map[string]any
			// uses[] dependency, found through discovery -- no address in the code
			if _, err := app.Call(r.Context(), heain.CallSpec{App: "conformance-ref", Capability: "ref.greet", Method: "POST", Path: "/v1/greet",
				Body: map[string]any{"name": "relayed " + str(body(r), "name")}, Out: &out}); err != nil {
				fail(w, err)
				return
			}
			reply(w, r, map[string]any{"relayed": out["greeting"]})
		},
	}
	for pat, fn := range h {
		if err := srv.HandleFunc(pat, fn); err != nil {
			log.Fatal(err)
		}
	}
	wk := app.NewWorker()
	_ = wk.Handle("ref.upper", func(ctx context.Context, j *heain.Job) ([]byte, error) {
		return []byte(strings.ToUpper(string(j.Payload))), nil
	})
	_ = wk.Handle("ref.label", func(ctx context.Context, j *heain.Job) ([]byte, error) {
		tone, conf := rate(string(j.Payload))
		if _, err := app.Reason(ctx, heain.Decision{Capability: "ref.label", Input: j.Payload, Decision: tone, Confidence: &conf,
			Summary: "counted exclamation marks", Role: "advisory", ModelSHA256: modelSHA256}); err != nil {
			return nil, err
		}
		return []byte(tone), nil
	})
	go func() {
		if app.WaitActive(ctx) == nil {
			_ = wk.Run(ctx)
		}
	}()
	l, err := net.Listen("tcp", heain.Listen("0.0.0.0:19443"))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("refapp: serving on %s", l.Addr())
	if err := srv.Serve(ctx, l); err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
	_ = app.Close(context.Background())
	log.Printf("refapp: deregistered")
}

func rate(text string) (string, float64) {
	if strings.Count(text, "!") >= 2 {
		return "loud", 0.9
	}
	return "calm", 0.7
}
