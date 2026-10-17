// Package core is the App API client (HEAIN spec 02-app-api.md): every call
// goes to heain-core over mTLS (TLS 1.3) with the app's certificate.
package core

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
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// Config says how to reach the core on this node.
type Config struct {
	// URL is the core's https base, e.g. https://127.0.0.1:18000.
	URL string
	// NodeID is the core's node id: its certificate must carry it (CN or
	// SAN), so the app talks to the core it expects and no other.
	NodeID string
	// CertFile/KeyFile: the app certificate (CN <app-id>.<instance-id>,
	// with the provisioning chain appended) and its key. CAFile: the
	// deployment's root CA.
	CertFile, KeyFile, CAFile string
	// Timeout per call (default 30 s; long polls set their own).
	Timeout time.Duration
}

// Client calls the App API.
type Client struct {
	base string
	hc   *http.Client
	lp   *http.Client // long polls: no client timeout, bounded by ctx
	cfg  Config

	tolerance atomic.Int64 // nanoseconds core's expired certificate is still accepted (0 = never)
	// OnExpiredCore is told when core's expired certificate is accepted
	// (within the tolerance); the SDK logs it.
	OnExpiredCore func(notAfter time.Time)
	expiredSeen   atomic.Int64 // NotAfter (unix) last reported
}

// New builds a client. It fails if the certificate files cannot be loaded.
func New(cfg Config) (*Client, error) {
	c := &Client{base: strings.TrimSuffix(cfg.URL, "/"), cfg: cfg}
	tc, err := tlsConfig(cfg.CertFile, cfg.KeyFile, cfg.CAFile, cfg.NodeID, c.ExpiredTolerance, c.noteExpired)
	if err != nil {
		return nil, err
	}
	if cfg.Timeout == 0 {
		c.cfg.Timeout = 30 * time.Second
	}
	tr := &http.Transport{TLSClientConfig: tc}
	c.hc, c.lp = &http.Client{Timeout: c.cfg.Timeout, Transport: tr}, &http.Client{Transport: tr}
	return c, nil
}

// SetExpiredTolerance sets how long after it expires core's certificate is
// still accepted (heain-core C2, a zone cut off for long): core tells an app
// with a safety capability (Registration.Safety) while its certificate still
// verifies; 0 = never (the default).
func (c *Client) SetExpiredTolerance(d time.Duration) {
	if d < 0 {
		d = 0
	}
	c.tolerance.Store(int64(d))
}

// ExpiredTolerance is the tolerance in force.
func (c *Client) ExpiredTolerance() time.Duration { return time.Duration(c.tolerance.Load()) }

func (c *Client) noteExpired(notAfter time.Time) {
	if c.expiredSeen.Swap(notAfter.Unix()) != notAfter.Unix() && c.OnExpiredCore != nil {
		c.OnExpiredCore(notAfter)
	}
}

// TLSConfig is the client side of the SDK's mTLS: TLS 1.3 only, the given
// client certificate, and the peer verified against caFile with serverName.
func TLSConfig(certFile, keyFile, caFile, serverName string) (*tls.Config, error) {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("heain-sdk: loading certificate: %w", err)
	}
	pool, err := LoadPool(caFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, RootCAs: pool, ServerName: serverName}, nil
}

// NodeCertOU marks a short-lived node certificate (heain-core's node-issuing CA).
const NodeCertOU = "heain-node"

// tlsConfig is TLSConfig whose peer check is done here instead of by
// crypto/tls -- the same checks (the chain to the CA at the current time,
// server authentication, serverName) -- so that core's short-lived node
// certificate may still be accepted for up to tolerance() after it expired
// (heain-core C2: core's zone cut off from the issuer for long). Nothing else
// is relaxed: the chain must verify at its last valid second.
func tlsConfig(certFile, keyFile, caFile, serverName string, tolerance func() time.Duration, expired func(time.Time)) (*tls.Config, error) {
	tc, err := TLSConfig(certFile, keyFile, caFile, serverName)
	if err != nil {
		return nil, err
	}
	pool := tc.RootCAs
	tc.InsecureSkipVerify = true // replaced by VerifyConnection (the same checks)
	tc.VerifyConnection = func(cs tls.ConnectionState) error {
		return VerifyCore(cs.PeerCertificates, pool, cs.ServerName, time.Now(), tolerance(), expired)
	}
	return tc, nil
}

// VerifyCore verifies core's certificate chain (leaf first) as crypto/tls
// would, except that a short-lived node certificate expired for at most
// tolerance is accepted when it verifies at its last valid second
// (expired, if set, is told).
func VerifyCore(certs []*x509.Certificate, pool *x509.CertPool, name string, now time.Time, tolerance time.Duration, expired func(time.Time)) error {
	if len(certs) == 0 {
		return errors.New("heain-sdk: core sent no certificate")
	}
	if name == "" {
		return errors.New("heain-sdk: no core node id to verify its certificate against")
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	opts := x509.VerifyOptions{Roots: pool, Intermediates: inter, CurrentTime: now, DNSName: name, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	_, err := certs[0].Verify(opts)
	if err == nil {
		return nil
	}
	leaf := certs[0]
	var inv x509.CertificateInvalidError
	if tolerance <= 0 || !errors.As(err, &inv) || inv.Reason != x509.Expired || !now.After(leaf.NotAfter) || now.Sub(leaf.NotAfter) > tolerance || !hasOU(leaf, NodeCertOU) {
		return &tls.CertificateVerificationError{UnverifiedCertificates: certs, Err: err}
	}
	opts.CurrentTime = leaf.NotAfter.Add(-time.Second)
	if _, err2 := leaf.Verify(opts); err2 != nil {
		return &tls.CertificateVerificationError{UnverifiedCertificates: certs, Err: err}
	}
	if expired != nil {
		expired(leaf.NotAfter)
	}
	return nil
}

func hasOU(c *x509.Certificate, ou string) bool {
	for _, o := range c.Subject.OrganizationalUnit {
		if o == ou {
			return true
		}
	}
	return false
}

// LoadPool reads a PEM CA bundle.
func LoadPool(caFile string) (*x509.CertPool, error) {
	raw, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("heain-sdk: reading CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("heain-sdk: no certificate in %s", caFile)
	}
	return pool, nil
}

// Error is the App API error body (spec 00 error format).
type Error struct {
	Status    int      `json:"-"`
	Code      string   `json:"code"`
	Message   string   `json:"message"`
	Retryable bool     `json:"retryable"`
	Reasons   []string `json:"reasons,omitempty"`
}

func (e *Error) Error() string {
	s := fmt.Sprintf("heain-core %d %s: %s", e.Status, e.Code, e.Message)
	if len(e.Reasons) > 0 {
		s += " (" + strings.Join(e.Reasons, "; ") + ")"
	}
	return s
}

// IsCode reports whether err is an App API error with code.
func IsCode(err error, code string) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == code
}

// Do sends method path with body (JSON-encoded unless nil) and decodes a 2xx
// JSON response into out (nil = ignore). It returns the HTTP status.
// Unknown response fields are ignored (spec 05 C11).
func (c *Client) Do(ctx context.Context, method, path string, hdr http.Header, body, out any) (int, error) {
	return c.do(c.hc, ctx, method, path, hdr, body, out)
}

// LongPoll is Do without the per-call timeout, for long polls (job claim);
// ctx bounds it.
func (c *Client) LongPoll(ctx context.Context, method, path string, body, out any) (int, error) {
	return c.do(c.lp, ctx, method, path, nil, body, out)
}

func (c *Client) do(hc *http.Client, ctx context.Context, method, path string, hdr http.Header, body, out any) (int, error) {
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return 0, err
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		var wrap struct {
			Error *Error `json:"error"`
		}
		if json.Unmarshal(data, &wrap) == nil && wrap.Error != nil {
			wrap.Error.Status = resp.StatusCode
			return resp.StatusCode, wrap.Error
		}
		return resp.StatusCode, &Error{Status: resp.StatusCode, Code: "http_" + fmt.Sprint(resp.StatusCode), Message: strings.TrimSpace(string(data))}
	}
	if out != nil && len(data) > 0 && resp.StatusCode != http.StatusNoContent {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, fmt.Errorf("heain-sdk: decoding %s %s: %w", method, path, err)
		}
	}
	return resp.StatusCode, nil
}

// Info is GET /v1/app/info.
type Info struct {
	CoreVersion string   `json:"core_version"`
	APIVersions []string `json:"api_versions"`
	NodeID      string   `json:"node_id"`
	Tier        string   `json:"tier"`
	Mode        string   `json:"mode"`
	// UserAssertionIssuers are the gateway apps (core gateway.apps).
	UserAssertionIssuers []string `json:"user_assertion_issuers,omitempty"`
	// ZoneMaster is the node id of this node's zone Master (this node's id
	// when it is the Master; core with zone keys, Stage B-1d).
	ZoneMaster string `json:"zone_master,omitempty"`
}

func (c *Client) Info(ctx context.Context) (Info, error) {
	var out Info
	_, err := c.Do(ctx, http.MethodGet, "/v1/app/info", nil, nil, &out)
	return out, err
}

// Registration is the answer to register and heartbeat.
type Registration struct {
	RegistrationID     string  `json:"registration_id"`
	Status             string  `json:"status"` // active | pending_approval | ...
	HeartbeatIntervalS int     `json:"heartbeat_interval_s,omitempty"`
	TTLS               int     `json:"ttl_s,omitempty"`
	ActionID           string  `json:"action_id,omitempty"`
	Safety             *Safety `json:"safety,omitempty"`
}

// Safety is what core tells an app with a safety capability (heain-core C2):
// how long after it expires core's certificate may still be accepted
// (security.safety_expired_max) and which of the app's capabilities are
// safety duties (license.safety_capabilities). Absent: none.
type Safety struct {
	ExpiredMaxS  int      `json:"expired_max_s"`
	Capabilities []string `json:"capabilities"`
}

// Register is POST /v1/app/register. manifest is sent as JSON.
func (c *Client) Register(ctx context.Context, manifest any, instanceID, endpointBase string) (Registration, error) {
	var out Registration
	_, err := c.Do(ctx, http.MethodPost, "/v1/app/register", nil,
		map[string]any{"manifest": manifest, "instance_id": instanceID, "endpoint_base": endpointBase}, &out)
	return out, err
}

func (c *Client) Heartbeat(ctx context.Context) (Registration, error) {
	var out Registration
	_, err := c.Do(ctx, http.MethodPost, "/v1/app/heartbeat", nil, struct{}{}, &out)
	return out, err
}

func (c *Client) Deregister(ctx context.Context) error {
	_, err := c.Do(ctx, http.MethodPost, "/v1/app/deregister", nil, struct{}{}, nil)
	return err
}
