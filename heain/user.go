package heain

// People through a gateway app (heain-gateway; core Step 4.6a, author
// decisions 2026-10-07).
//
// A gateway app (one listed in core's 2b key gateway.apps) signs, for every
// request it passes on for a signed-in person, a UserAssertion with the key
// of its app certificate and sends it as X-Heain-User. The Server checks it
// before the handler runs:
//
//   - the caller is an instance of a gateway app (core's /v1/app/info names
//     them as user_assertion_issuers) and the assertion is signed by the key
//     of the very certificate the call came with (iss = that instance);
//   - it is for this app (aud), this method and path, this trace id, and
//     fresh (at most AssertionMaxAge; each id is accepted once);
//   - the endpoint is declared public in the manifest (endpoints[].public)
//     -- a person reaches only what the app chose to expose.
//
// The handler reads the person with User(ctx); the audit event of a formal
// endpoint carries the person and the whole signed assertion, so who acted
// can be proved later (VerifyUserAssertion). Authorization stays split
// (author decision 4): the gateway checks the route's roles at the door, the
// app checks data-level rights itself from User(ctx).

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// HeaderUser carries a signed UserAssertion (base64url of its JSON).
const HeaderUser = "X-Heain-User"

// AssertionMaxAge bounds how long an assertion is valid.
const AssertionMaxAge = 2 * time.Minute

// UserAssertion says which signed-in person a request is for.
type UserAssertion struct {
	Version    int      `json:"v"`
	ID         string   `json:"id"`
	Issuer     string   `json:"iss"` // the gateway instance: <app-id>.<instance-id>
	Audience   string   `json:"aud"` // the app called
	Method     string   `json:"method"`
	Path       string   `json:"path"`
	Trace      string   `json:"trace"`
	Subject    string   `json:"sub"` // the person's account id
	Name       string   `json:"name,omitempty"`
	Roles      []string `json:"roles,omitempty"`
	AuthMethod string   `json:"amr"` // e.g. password+totp, oidc:<issuer>
	Session    string   `json:"sid,omitempty"`
	IssuedAt   string   `json:"iat"`
	Expires    string   `json:"exp"`
	Signature  string   `json:"sig,omitempty"`
}

// User is the signed-in person a request is for.
type User struct {
	ID         string
	Name       string
	Roles      []string
	AuthMethod string
	Session    string
	Gateway    string // the gateway instance that vouched for the person
	Assertion  string // the signed assertion as received (for the app's own records)
}

// HasRole reports whether u holds role.
func (u *User) HasRole(role string) bool {
	if u == nil {
		return false
	}
	for _, r := range u.Roles {
		if r == role {
			return true
		}
	}
	return false
}

type userKey struct{}

// User is the signed-in person of this request, or nil (a call from an app,
// or an anonymous route of the gateway).
func UserOf(ctx context.Context) *User { u, _ := ctx.Value(userKey{}).(*User); return u }

// SignUserAssertion (for a gateway app) fills in id, issuer, times and the
// signature of u and returns the X-Heain-User header value. The caller
// sets aud, method, path, trace and the person.
func (a *App) SignUserAssertion(u UserAssertion) (string, error) {
	if u.Audience == "" || u.Method == "" || u.Path == "" || u.Trace == "" || u.Subject == "" {
		return "", errors.New("heain-sdk: a user assertion needs aud, method, path, trace and sub")
	}
	now := time.Now().UTC()
	u.Version, u.ID, u.Issuer = 1, NewID(), a.Manifest.App.ID+"."+a.Instance
	u.IssuedAt, u.Expires = now.Format(time.RFC3339Nano), now.Add(AssertionMaxAge/2).Format(time.RFC3339Nano)
	u.Signature = ""
	canon, err := Canonical(u)
	if err != nil {
		return "", err
	}
	signer, ok := a.key.(crypto.Signer)
	if !ok {
		return "", errors.New("heain-sdk: the app key cannot sign")
	}
	h := sha256.Sum256(canon)
	sig, err := signer.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		return "", err
	}
	u.Signature = base64.StdEncoding.EncodeToString(sig)
	b, err := json.Marshal(u)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ParseUserAssertion decodes a header value (no checks).
func ParseUserAssertion(v string) (UserAssertion, error) {
	var u UserAssertion
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(v))
	if err != nil {
		return u, fmt.Errorf("not base64url: %w", err)
	}
	if err := json.Unmarshal(b, &u); err != nil {
		return u, fmt.Errorf("not an assertion: %w", err)
	}
	return u, nil
}

// VerifyUserAssertion checks u's signature against the certificate of the
// gateway instance that signed it (also for auditors, later).
func VerifyUserAssertion(u UserAssertion, cert *x509.Certificate) error {
	sig, err := base64.StdEncoding.DecodeString(u.Signature)
	if err != nil || len(sig) == 0 {
		return errors.New("no signature")
	}
	u.Signature = ""
	canon, err := Canonical(u)
	if err != nil {
		return err
	}
	h := sha256.Sum256(canon)
	switch k := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, h[:], sig) {
			return errors.New("signature does not verify")
		}
		return nil
	case *rsa.PublicKey:
		if rsa.VerifyPKCS1v15(k, crypto.SHA256, h[:], sig) != nil {
			return errors.New("signature does not verify")
		}
		return nil
	}
	return errors.New("unsupported key type")
}

// issuers caches core's user_assertion_issuers.
type issuerCache struct {
	mu  sync.Mutex
	ids []string
	at  time.Time
}

// IssuerTTL is how long the list of gateway apps is cached.
var IssuerTTL = 15 * time.Second

func (a *App) assertionIssuers(ctx context.Context) ([]string, error) {
	a.issuers.mu.Lock()
	defer a.issuers.mu.Unlock()
	if !a.issuers.at.IsZero() && time.Since(a.issuers.at) < IssuerTTL {
		return a.issuers.ids, nil
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	info, err := a.Core.Info(cctx)
	if err != nil {
		return nil, err
	}
	a.issuers.ids, a.issuers.at = info.UserAssertionIssuers, time.Now()
	return a.issuers.ids, nil
}

// seenAssertions refuses an assertion id a second time.
type seenAssertions struct {
	mu sync.Mutex
	m  map[string]time.Time
}

func (s *seenAssertions) first(id string, until time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if s.m == nil {
		s.m = map[string]time.Time{}
	}
	if len(s.m) > 10000 {
		for k, t := range s.m {
			if now.After(t) {
				delete(s.m, k)
			}
		}
	}
	if t, ok := s.m[id]; ok && now.Before(t) {
		return false
	}
	s.m[id] = until.Add(time.Minute)
	return true
}

// userAssertionError is why an assertion was refused.
type userAssertionError struct{ msg string }

func (e *userAssertionError) Error() string { return e.msg }

// checkUser verifies r's X-Heain-User (if any) for an endpoint; nil user and
// nil error when there is none.
func (s *Server) checkUser(r *http.Request, public bool, trace string) (*User, error) {
	v := r.Header.Get(HeaderUser)
	if v == "" {
		return nil, nil
	}
	bad := func(f string, a ...any) error { return &userAssertionError{fmt.Sprintf(f, a...)} }
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, bad("a user assertion needs the gateway's certificate")
	}
	leaf := r.TLS.PeerCertificates[0]
	caller := leaf.Subject.CommonName
	callerApp, _, _ := strings.Cut(caller, ".")
	ids, err := s.app.assertionIssuers(r.Context())
	if err != nil {
		return nil, fmt.Errorf("heain-sdk: the gateway list is unavailable: %w", err)
	}
	trusted := false
	for _, id := range ids {
		if id == callerApp {
			trusted = true
		}
	}
	if !trusted {
		return nil, bad("%s is not a gateway app (core gateway.apps)", callerApp)
	}
	if !public {
		return nil, bad("this endpoint is not declared public: a person cannot reach it")
	}
	u, err := ParseUserAssertion(v)
	if err != nil {
		return nil, bad("%v", err)
	}
	if err := VerifyUserAssertion(u, leaf); err != nil {
		return nil, bad("assertion: %v", err)
	}
	switch {
	case u.Version != 1:
		return nil, bad("assertion version %d", u.Version)
	case u.Issuer != caller:
		return nil, bad("assertion issued by %q, the call came from %q", u.Issuer, caller)
	case u.Audience != s.app.Manifest.App.ID:
		return nil, bad("assertion is for %q", u.Audience)
	case u.Method != r.Method || u.Path != r.URL.Path:
		return nil, bad("assertion is for %s %s", u.Method, u.Path)
	case u.Trace != trace:
		return nil, bad("assertion is for another trace")
	case u.Subject == "":
		return nil, bad("assertion names no person")
	}
	iat, err1 := time.Parse(time.RFC3339Nano, u.IssuedAt)
	exp, err2 := time.Parse(time.RFC3339Nano, u.Expires)
	now := time.Now()
	if err1 != nil || err2 != nil || exp.Sub(iat) > AssertionMaxAge || now.Before(iat.Add(-30*time.Second)) || now.After(exp.Add(30*time.Second)) {
		return nil, bad("assertion expired or not yet valid")
	}
	if !s.seen.first(u.ID, exp) {
		return nil, bad("assertion %s was already used", u.ID)
	}
	return &User{ID: u.Subject, Name: u.Name, Roles: append([]string(nil), u.Roles...), AuthMethod: u.AuthMethod, Session: u.Session,
		Gateway: caller, Assertion: v}, nil
}
