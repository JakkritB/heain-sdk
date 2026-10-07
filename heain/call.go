package heain

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/heainframework/heain-sdk/core"
)

// Instance is one live provider of a capability (GET /v1/app/discover).
type Instance struct {
	AppID        string `json:"app_id"`
	AppVersion   string `json:"app_version"`
	InstanceID   string `json:"instance_id"`
	EndpointBase string `json:"endpoint_base,omitempty"`
	Execution    string `json:"execution"`
	Lane         string `json:"lane,omitempty"`
}

// DiscoverTTL is how long discovery answers are cached.
var DiscoverTTL = 10 * time.Second

type discoCache struct {
	mu   sync.Mutex
	at   map[string]time.Time
	data map[string][]Instance
	rr   map[string]int
}

// Discover finds live instances providing capability (version 0 = any).
// Answers are cached for DiscoverTTL.
func (a *App) Discover(ctx context.Context, capability string, version int) ([]Instance, error) {
	key := capability + "@" + strconv.Itoa(version)
	a.disco.mu.Lock()
	if a.disco.at == nil {
		a.disco.at, a.disco.data, a.disco.rr = map[string]time.Time{}, map[string][]Instance{}, map[string]int{}
	}
	if t, ok := a.disco.at[key]; ok && time.Since(t) < DiscoverTTL {
		out := a.disco.data[key]
		a.disco.mu.Unlock()
		return out, nil
	}
	a.disco.mu.Unlock()
	q := url.Values{"capability": {capability}}
	if version > 0 {
		q.Set("version", strconv.Itoa(version))
	}
	var out struct {
		Instances []Instance `json:"instances"`
	}
	if _, err := a.Core.Do(ctx, http.MethodGet, "/v1/app/discover?"+q.Encode(), nil, nil, &out); err != nil {
		return nil, err
	}
	a.disco.mu.Lock()
	a.disco.at[key], a.disco.data[key] = time.Now(), out.Instances
	a.disco.mu.Unlock()
	return out.Instances, nil
}

// ErrNotDeclared is returned for a call to a dependency the manifest's
// uses[] does not declare (enforced, decided 2026-10-05; spec 05 C12).
var ErrNotDeclared = errors.New("not declared in the manifest's uses[]")

// ErrNoInstance is returned when no live instance provides the capability.
var ErrNoInstance = errors.New("no live instance provides this capability")

// CallSpec is one direct app-to-app call.
type CallSpec struct {
	App, Capability string
	Version         int
	// Instance, when set, calls only that instance of App (for work that
	// must reach every instance, such as a data-subject request).
	Instance     string
	Method, Path string
	Body         any // JSON-encoded unless []byte
	Out          any // decoded from a 2xx JSON answer
	// Timeout bounds the whole call, answer included (default
	// DefaultCallTimeout). Calls that move large data (a module's split
	// or merge of a long video) set a longer one.
	Timeout time.Duration
}

// DefaultCallTimeout bounds a direct call that sets no Timeout.
const DefaultCallTimeout = 30 * time.Second

// CallError is a non-2xx answer from the called app.
type CallError struct {
	Status int
	Code   string
	Body   string
}

func (e *CallError) Error() string {
	return fmt.Sprintf("heain-sdk: call answered %d %s %s", e.Status, e.Code, e.Body)
}

// Call makes a direct call to another app over mTLS (spec 02 §4): only to a
// dependency declared in uses[], resolved through discovery, with the
// callee's certificate checked to be that app's. The trace id of ctx is
// carried on unless the callee's lane differs from ctx's lane, in which case
// a fresh one is started (so no id crosses lanes).
func (a *App) Call(ctx context.Context, cs CallSpec) (int, error) {
	if !a.declares(cs.App, cs.Capability) {
		return 0, fmt.Errorf("heain-sdk: %s/%s %w", cs.App, cs.Capability, ErrNotDeclared)
	}
	insts, err := a.Discover(ctx, cs.Capability, cs.Version)
	if err != nil {
		return 0, err
	}
	var cands []Instance
	for _, in := range insts {
		if in.AppID == cs.App && in.Execution == "direct" && in.EndpointBase != "" && (cs.Instance == "" || in.InstanceID == cs.Instance) {
			cands = append(cands, in)
		}
	}
	if len(cands) == 0 {
		return 0, fmt.Errorf("heain-sdk: %s/%s: %w", cs.App, cs.Capability, ErrNoInstance)
	}
	to := cs.Timeout
	if to <= 0 {
		to = DefaultCallTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	a.disco.mu.Lock()
	n := a.disco.rr[cs.Capability]
	a.disco.rr[cs.Capability] = n + 1
	a.disco.mu.Unlock()
	target := cands[n%len(cands)]

	trace := TraceID(ctx)
	if trace == "" || Lane(ctx) != target.Lane {
		trace = NewID()
	}
	var rd io.Reader
	if b, ok := cs.Body.([]byte); ok {
		rd = bytes.NewReader(b)
	} else if cs.Body != nil {
		raw, err := json.Marshal(cs.Body)
		if err != nil {
			return 0, err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, cs.Method, strings.TrimSuffix(target.EndpointBase, "/")+cs.Path, rd)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderTrace, trace)
	if target.Lane != "" {
		req.Header.Set(HeaderLane, target.Lane)
	}
	hc, err := a.appClient(target.AppID + "." + target.InstanceID)
	if err != nil {
		return 0, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		ce := &CallError{Status: resp.StatusCode, Body: strings.TrimSpace(string(data))}
		var wrap struct {
			Error *core.Error `json:"error"`
		}
		if json.Unmarshal(data, &wrap) == nil && wrap.Error != nil {
			ce.Code = wrap.Error.Code
		}
		return resp.StatusCode, ce
	}
	if cs.Out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, cs.Out); err != nil {
			return resp.StatusCode, err
		}
	}
	return resp.StatusCode, nil
}

func (a *App) declares(app, capability string) bool {
	return a.Manifest.DependsOn(app, capability)
}

// appClient is an mTLS client that accepts only the app instance want
// (<app-id>.<instance-id>): its certificate must chain to the deployment
// CA and be an app certificate with that CN. App certificates carry no
// DNS names, so the name check is done here instead of by hostname.
func (a *App) appClient(want string) (*http.Client, error) {
	if c, ok := a.clients.Load(want); ok {
		return c.(*http.Client), nil
	}
	pool, err := core.LoadPool(a.opts.Core.CAFile)
	if err != nil {
		return nil, err
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{a.pair},
		InsecureSkipVerify: true, // replaced by VerifyConnection below
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no peer certificate")
			}
			inter := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				inter.AddCert(c)
			}
			leaf := cs.PeerCertificates[0]
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
				return fmt.Errorf("peer certificate: %w", err)
			}
			if !isAppCert(leaf) || leaf.Subject.CommonName != want {
				return fmt.Errorf("peer is %q, expected app instance %q", leaf.Subject.CommonName, want)
			}
			return a.checkPeer(context.Background(), leaf)
		}}
	c, _ := a.clients.LoadOrStore(want, &http.Client{Transport: &http.Transport{TLSClientConfig: tc}})
	return c.(*http.Client), nil
}
