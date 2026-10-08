package heain

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/heainframework/heain-sdk/core"
	"github.com/heainframework/heain-sdk/manifest"
)

// Server serves an app's direct endpoints (spec 01 endpoints[]) over mTLS:
//   - only endpoints declared in the manifest can be handled;
//   - a capability with a lane requires X-Heain-Lane to match, and a trace
//     id seen in one lane of an unlinkable pair is refused in the other
//     (lane_violation, spec 01 §3);
//   - every call to a formal endpoint, refused or not, produces exactly one
//     audit event at core; non-formal endpoints produce none (spec 05 C5);
//   - an ai.used capability whose record is required must produce a
//     reasoning record (App.Reason) in a successful call (C6).
type Server struct {
	app      *App
	mux      *http.ServeMux
	handled  map[string]bool
	traces   traceLanes
	unlinked map[string]map[string]bool
	seen     seenAssertions
}

// NewServer prepares the direct-endpoint server.
func (a *App) NewServer() *Server {
	s := &Server{app: a, mux: http.NewServeMux(), handled: map[string]bool{}, unlinked: map[string]map[string]bool{}}
	for _, p := range a.Manifest.Lanes.Unlinkable {
		if len(p) == 2 {
			if s.unlinked[p[0]] == nil {
				s.unlinked[p[0]] = map[string]bool{}
			}
			if s.unlinked[p[1]] == nil {
				s.unlinked[p[1]] = map[string]bool{}
			}
			s.unlinked[p[0]][p[1]], s.unlinked[p[1]][p[0]] = true, true
		}
	}
	return s
}

// Handle registers h for a declared endpoint, written "METHOD /path"
// exactly as in the manifest (e.g. "GET /v1/grants/{id}").
func (s *Server) Handle(pattern string, h http.Handler) error {
	method, path, ok := strings.Cut(pattern, " ")
	if !ok {
		return fmt.Errorf("heain-sdk: pattern must be \"METHOD /path\"")
	}
	var ep *manifest.Endpoint
	for i, e := range s.app.Manifest.Endpoints {
		if strings.EqualFold(e.Method, method) && e.Path == path {
			ep = &s.app.Manifest.Endpoints[i]
		}
	}
	if ep == nil {
		return fmt.Errorf("heain-sdk: %s is not declared in the manifest's endpoints", pattern)
	}
	c, _ := s.app.Manifest.Capability(ep.Capability)
	s.mux.Handle(strings.ToUpper(method)+" "+path, s.wrap(*ep, c, h))
	s.handled[strings.ToUpper(method)+" "+path] = true
	return nil
}

// HandleFunc is Handle for a function.
func (s *Server) HandleFunc(pattern string, f func(http.ResponseWriter, *http.Request)) error {
	return s.Handle(pattern, http.HandlerFunc(f))
}

// TLSConfig is the server's mTLS: the app certificate, TLS 1.3, and a
// client certificate from the deployment CA that is an app certificate.
func (s *Server) TLSConfig() (*tls.Config, error) {
	pool, err := core.LoadPool(s.app.opts.Core.CAFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{s.app.pair},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}, nil
}

// Serve serves on l until ctx ends. Every declared endpoint must have a
// handler first.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	for _, e := range s.app.Manifest.Endpoints {
		if !s.handled[strings.ToUpper(e.Method)+" "+e.Path] {
			return fmt.Errorf("heain-sdk: endpoint %s %s is declared but has no handler", e.Method, e.Path)
		}
	}
	tc, err := s.TLSConfig()
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: s.mux, TLSConfig: tc, ReadHeaderTimeout: 10 * time.Second}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	err = srv.Serve(tls.NewListener(l, tc))
	if ctx.Err() != nil {
		return nil
	}
	return err
}

// ListenAndServe listens on addr and serves.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.Serve(ctx, l)
}

type recorder struct {
	hdr    http.Header
	status int
	body   bytes.Buffer
	// a streamed answer (StreamBody): at the first byte or status the
	// checks and the formal audit run (finish), then the body goes straight
	// to the client
	stream bool
	finish func(status int) bool
	sent   bool // finish ran
	ok     bool // finish passed: writes go to out
	out    http.ResponseWriter
}

func (r *recorder) Header() http.Header { return r.hdr }
func (r *recorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	if r.stream && !r.sent {
		r.sent = true
		r.ok = r.finish(r.status)
	}
}
func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.WriteHeader(http.StatusOK)
	}
	if r.stream {
		if !r.ok {
			return 0, errStreamRefused
		}
		return r.out.Write(b)
	}
	return r.body.Write(b)
}

// Flush passes a flush on to a streamed answer.
func (r *recorder) Flush() {
	if r.stream && r.ok {
		if f, ok := r.out.(http.Flusher); ok {
			f.Flush()
		}
	}
}

var errStreamRefused = errors.New("heain-sdk: the streamed answer was withheld (its formal audit failed)")

// StreamBody makes the answer of the endpoint being served go to the caller
// as it is written instead of after the handler returns (Stage B-1e: a
// file's content). Call it before writing anything. The formal audit is
// written when the status is set or the first byte written; if it cannot
// be, the caller gets 503 audit_unavailable and every Write fails. Without
// a heain-sdk server around w it does nothing.
func StreamBody(w http.ResponseWriter) {
	if r, ok := w.(*recorder); ok && r.status == 0 {
		r.stream = true
	}
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": code, "message": msg, "retryable": status >= 500}})
}

func (s *Server) wrap(ep manifest.Endpoint, c manifest.Capability, h http.Handler) http.Handler {
	formal := ep.Formal != nil && *ep.Formal
	recordRequired := c.AI.Used != nil && *c.AI.Used && c.AI.ReasoningRecord != "optional"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller := ""
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			caller = r.TLS.PeerCertificates[0].Subject.CommonName
			if !isAppCert(r.TLS.PeerCertificates[0]) {
				writeErr(w, http.StatusForbidden, "identity_mismatch", "an app certificate is required")
				return
			}
			if err := s.app.checkPeer(r.Context(), r.TLS.PeerCertificates[0]); err != nil {
				if errors.Is(err, ErrRevoked) {
					writeErr(w, http.StatusForbidden, "certificate_revoked", "the caller's app certificate is no longer valid")
				} else {
					writeErr(w, http.StatusServiceUnavailable, "revocation_unavailable", "the caller's certificate status could not be checked with core")
				}
				return
			}
		}
		trace := r.Header.Get(HeaderTrace)
		if trace == "" {
			trace = NewID()
		}
		lane := r.Header.Get(HeaderLane)
		var user *User
		audit := func(outcome string, detail map[string]any) error {
			if !formal {
				return nil
			}
			detail["method"], detail["path"] = ep.Method, ep.Path
			if user != nil {
				detail["user"], detail["user_assertion"] = user.ID, user.Assertion
			}
			return s.app.auditEvent(r.Context(), trace, c.Lane, c.Name, caller, outcome, detail)
		}
		if !s.app.allowedFresh(r.Context(), c.Name) {
			_ = audit("refused:standalone_not_allowed", map[string]any{})
			writeErr(w, http.StatusConflict, "standalone_not_allowed", "this node is standalone and "+c.Name+" is not allowed offline (manifest offline.allowed or the admin's offline policy)")
			return
		}
		if c.Lane != "" && lane != c.Lane {
			trace = NewID() // a refused id must not be linked into this lane's audit
			_ = audit("refused:lane_violation", map[string]any{"lane_sent": lane})
			writeErr(w, http.StatusBadRequest, "lane_violation", fmt.Sprintf("%s belongs to lane %q; send %s: %s", c.Name, c.Lane, HeaderLane, c.Lane))
			return
		}
		if c.Lane != "" {
			if other, crossed := s.traces.check(trace, c.Lane, s.unlinked[c.Lane]); crossed {
				trace = NewID() // the crossing id is not written into this lane's audit
				_ = audit("refused:lane_violation", map[string]any{"crossed_from": other})
				writeErr(w, http.StatusBadRequest, "lane_violation", fmt.Sprintf("this trace id was used in lane %q, which is unlinkable from %q", other, c.Lane))
				return
			}
		}
		u, err := s.checkUser(r, ep.Public, trace)
		if err != nil {
			var ue *userAssertionError
			if errors.As(err, &ue) {
				_ = audit("refused:user_assertion_invalid", map[string]any{"reason": ue.msg})
				writeErr(w, http.StatusUnauthorized, "user_assertion_invalid", ue.msg)
				return
			}
			writeErr(w, http.StatusServiceUnavailable, "user_assertion_unavailable", err.Error())
			return
		}
		user = u
		sink := &recordSink{}
		ctx := context.WithValue(WithTrace(r.Context(), trace, c.Lane), keyCaller, caller)
		if user != nil {
			ctx = context.WithValue(ctx, userKey{}, user)
		}
		ctx = context.WithValue(ctx, keyRecords, sink)
		rec := &recorder{hdr: http.Header{}, out: w}
		rec.finish = func(status int) bool {
			ids := sink.list()
			if recordRequired && status < 400 && len(ids) == 0 {
				_ = audit("error:reasoning_record_missing", map[string]any{"status": status})
				s.app.logf("heain-sdk: %s %s answered without the reasoning record %s requires -- refused", ep.Method, ep.Path, c.Name)
				writeErr(w, http.StatusInternalServerError, "reasoning_record_missing", c.Name+" uses AI and must send a reasoning record (App.Reason) for every decision")
				return false
			}
			outcome := "ok"
			if status >= 400 {
				outcome = fmt.Sprintf("error:%d", status)
			}
			detail := map[string]any{"status": status}
			if len(ids) > 0 {
				detail["reasoning_record_ids"] = ids
			}
			if rec.stream {
				detail["streamed"] = true
			}
			if err := audit(outcome, detail); err != nil {
				s.app.logf("heain-sdk: audit of %s %s failed, response withheld: %v", ep.Method, ep.Path, err)
				writeErr(w, http.StatusServiceUnavailable, "audit_unavailable", "the formal process could not be logged")
				return false
			}
			for k, v := range rec.hdr {
				w.Header()[k] = v
			}
			w.Header().Set(HeaderTrace, trace)
			w.WriteHeader(status)
			return true
		}
		h.ServeHTTP(rec, r.WithContext(ctx))
		if rec.status == 0 {
			rec.status = http.StatusOK
		}
		if rec.stream {
			if !rec.sent {
				rec.WriteHeader(rec.status)
			}
			return
		}
		if rec.finish(rec.status) {
			_, _ = w.Write(rec.body.Bytes())
		}
	})
}

func isAppCert(c *x509.Certificate) bool {
	for _, ou := range c.Subject.OrganizationalUnit {
		if ou == AppCertOU {
			return true
		}
	}
	return false
}

// AppCertOU marks certificates issued by core's provisioning to apps.
const AppCertOU = "heain-sdk-client"

// auditEvent writes one formal event to core (spec 02 §8), retrying briefly.
func (a *App) auditEvent(ctx context.Context, trace, lane, capability, actor, outcome string, detail map[string]any) error {
	body := map[string]any{"trace_id": trace, "lane": lane, "capability": capability, "actor": actor,
		"outcome": outcome, "at": time.Now().UTC().Format(time.RFC3339Nano), "detail": detail}
	var err error
	for i := 0; i < 3; i++ {
		if _, err = a.Core.Do(ctx, http.MethodPost, "/v1/app/audit/events", nil, body, nil); err == nil {
			return nil
		}
		time.Sleep(time.Duration(200*(i+1)) * time.Millisecond)
	}
	return err
}

// Audit writes a formal event for work the app did outside a served call
// (for example a job it ran). capability must be in the manifest.
func (a *App) Audit(ctx context.Context, capability, outcome string, detail map[string]any) error {
	c, ok := a.Manifest.Capability(capability)
	if !ok {
		return fmt.Errorf("heain-sdk: %s is not in the manifest", capability)
	}
	if detail == nil {
		detail = map[string]any{}
	}
	trace := TraceID(ctx)
	if trace == "" {
		trace = NewID()
	}
	return a.auditEvent(ctx, trace, c.Lane, c.Name, a.Manifest.App.ID+"."+a.Instance, outcome, detail)
}

// traceLanes remembers, for a while, which lane each trace id was seen in.
type traceLanes struct {
	mu   sync.Mutex
	seen map[string]laneSeen
}

type laneSeen struct {
	lane string
	at   time.Time
}

func (t *traceLanes) check(trace, lane string, unlinkable map[string]bool) (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.seen == nil {
		t.seen = map[string]laneSeen{}
	}
	now := time.Now()
	if len(t.seen) > 100000 {
		for k, v := range t.seen {
			if now.Sub(v.at) > time.Hour {
				delete(t.seen, k)
			}
		}
	}
	if prev, ok := t.seen[trace]; ok && prev.lane != lane && unlinkable[prev.lane] {
		return prev.lane, true
	}
	t.seen[trace] = laneSeen{lane: lane, at: now}
	return "", false
}
