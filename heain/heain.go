// Package heain is the entry point of heain-sdk: an app calls Start with
// its manifest and certificate, and gets a registered, heart-beating
// connection to the heain-core on its node.
//
//	app, err := heain.Start(ctx, heain.Options{ManifestPath: "heain-app.yaml", InstanceID: "a1", Core: cfg})
//	if err != nil { log.Fatal(err) }   // an invalid manifest never starts
//	defer app.Close(context.Background())
package heain

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/heainframework/heain-sdk/core"
	"github.com/heainframework/heain-sdk/manifest"
)

// SDK identity, checked against the manifest's app.sdk.
const (
	SDKName    = "heain-sdk-go"
	SDKVersion = "1.0.0"
)

// Options configure Start.
type Options struct {
	ManifestPath string
	InstanceID   string
	// EndpointBase is this instance's https base for direct capabilities
	// (empty for job-only apps).
	EndpointBase string
	Core         core.Config
	// StateDir holds the SDK's small durable state (the journal's app_seq
	// counter). Default: the directory of Core.KeyFile.
	StateDir string
	// ModePoll is how often the node's mode (normal/standalone) is read
	// from core (default 5 s; < 0 disables, then Mode is read on demand only).
	ModePoll time.Duration
	// Logf receives the SDK's own log lines (default log.Printf).
	Logf func(format string, a ...any)
}

// App is a running, registered app instance.
type App struct {
	Manifest manifest.Manifest
	Core     *core.Client
	Instance string

	mu      sync.Mutex
	reg     core.Registration
	opts    Options
	pair    tls.Certificate
	key     crypto.PrivateKey
	disco   discoCache
	clients sync.Map // app instance -> *http.Client (appClient)
	stop    chan struct{}
	done    chan struct{}
	logf    func(string, ...any)
	closed  bool

	modeMu   sync.Mutex
	mode     Mode
	modeAt   time.Time
	modeSubs []func(old, cur Mode)
	modeDone chan struct{}
	seqMu    sync.Mutex // journal app_seq counter
	certs    certCache  // peer certificate status (revocation.go)
}

// ErrIdentity is returned when the certificate's CN is not <app-id>.<instance-id>.
var ErrIdentity = errors.New("identity_mismatch")

// Start loads and validates the manifest (an invalid one never starts, spec
// 01 §4), checks the certificate identity, checks that the core serves the
// manifest's API, registers, and keeps the registration alive.
func Start(ctx context.Context, o Options) (*App, error) {
	logf := o.Logf
	if logf == nil {
		logf = log.Printf
	}
	m, err := manifest.Load(o.ManifestPath)
	if err != nil {
		return nil, err
	}
	if err := manifest.Validate(m); err != nil {
		return nil, err
	}
	if err := manifest.CheckSDK(m, SDKName, SDKVersion); err != nil {
		return nil, err
	}
	if o.InstanceID == "" {
		return nil, fmt.Errorf("heain-sdk: InstanceID is required")
	}
	want := m.App.ID + "." + o.InstanceID
	cn, err := certCN(o.Core.CertFile)
	if err != nil {
		return nil, err
	}
	if cn != want {
		return nil, fmt.Errorf("%w: certificate CN is %q, the manifest and instance need %q", ErrIdentity, cn, want)
	}
	c, err := core.New(o.Core)
	if err != nil {
		return nil, err
	}
	info, err := c.Info(ctx)
	if err != nil {
		return nil, fmt.Errorf("heain-sdk: core unreachable: %w", err)
	}
	served := false
	for _, v := range info.APIVersions {
		if v == m.App.API {
			served = true
		}
	}
	if !served {
		return nil, &manifest.ValidationError{Code: manifest.CodeAPIUnsupported, Reasons: []string{fmt.Sprintf("core %s serves %v, the manifest targets %s", info.CoreVersion, info.APIVersions, m.App.API)}}
	}
	pair, err := tls.LoadX509KeyPair(o.Core.CertFile, o.Core.KeyFile)
	if err != nil {
		return nil, err
	}
	reg, err := c.Register(ctx, m, o.InstanceID, o.EndpointBase)
	if err != nil {
		return nil, err
	}
	a := &App{Manifest: m, Core: c, Instance: o.InstanceID, reg: reg, stop: make(chan struct{}), done: make(chan struct{}), logf: logf,
		opts: o, pair: pair, key: pair.PrivateKey}
	logf("heain-sdk: %s registered with core %s (%s), status %s", want, info.NodeID, info.CoreVersion, reg.Status)
	a.mode = Mode{Mode: ModeNormal}
	if info.Mode != "" {
		a.mode.Mode = info.Mode
	}
	a.modeDone = make(chan struct{})
	go a.heartbeat()
	go a.watchMode()
	return a, nil
}

func certCN(certFile string) (string, error) {
	raw, err := os.ReadFile(certFile)
	if err != nil {
		return "", fmt.Errorf("heain-sdk: reading certificate: %w", err)
	}
	b, _ := pem.Decode(raw)
	if b == nil {
		return "", fmt.Errorf("heain-sdk: %s holds no PEM certificate", certFile)
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return "", err
	}
	return cert.Subject.CommonName, nil
}

// Status is the registration status as last seen (active, pending_approval, ...).
func (a *App) Status() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.reg.Status
}

// Registration is the last registration answer.
func (a *App) Registration() core.Registration {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.reg
}

// WaitActive blocks until the registration is active (an Approver may first
// have to admit a new app or version) or ctx ends.
func (a *App) WaitActive(ctx context.Context) error {
	for {
		if a.Status() == "active" {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("heain-sdk: registration still %s: %w", a.Status(), ctx.Err())
		case <-time.After(time.Second):
			if r, err := a.Core.Heartbeat(ctx); err == nil {
				a.mu.Lock()
				a.reg.Status = r.Status
				a.mu.Unlock()
			}
		}
	}
}

func (a *App) heartbeat() {
	defer close(a.done)
	for {
		every := time.Duration(a.Registration().HeartbeatIntervalS) * time.Second
		if every <= 0 {
			every = 10 * time.Second
		}
		select {
		case <-a.stop:
			return
		case <-time.After(every):
		}
		ctx, cancel := context.WithTimeout(context.Background(), every)
		r, err := a.Core.Heartbeat(ctx)
		cancel()
		if err != nil {
			a.logf("heain-sdk: heartbeat failed: %v", err)
			continue
		}
		a.mu.Lock()
		a.reg.Status = r.Status
		a.mu.Unlock()
	}
}

// Close stops the heartbeat and deregisters (graceful leave).
func (a *App) Close(ctx context.Context) error {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil
	}
	a.closed = true
	a.mu.Unlock()
	close(a.stop)
	<-a.done
	<-a.modeDone
	return a.Core.Deregister(ctx)
}
