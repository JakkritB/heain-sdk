package heain

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// RevocationTTL is how long a certificate status from core is reused
// (core caches the Master's answer for the same time).
var RevocationTTL = 10 * time.Second

// ErrRevoked: the peer's app certificate is no longer valid (revoked,
// expired or past its probation) according to core.
var ErrRevoked = errors.New("certificate_revoked")

type certCache struct {
	mu sync.Mutex
	m  map[string]certStatus
}

type certStatus struct {
	valid bool
	at    time.Time
}

// checkPeer asks core whether an app certificate is still valid (GET
// /v1/app/certs/{serial}, core 1.3). Fail closed: if core cannot answer,
// the peer is refused.
func (a *App) checkPeer(ctx context.Context, cert *x509.Certificate) error {
	serial := cert.SerialNumber.String()
	a.certs.mu.Lock()
	if a.certs.m == nil {
		a.certs.m = map[string]certStatus{}
	}
	st, ok := a.certs.m[serial]
	a.certs.mu.Unlock()
	if !ok || time.Since(st.at) > RevocationTTL {
		var out struct {
			Valid bool `json:"valid"`
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		_, err := a.Core.Do(cctx, http.MethodGet, "/v1/app/certs/"+serial, nil, nil, &out)
		cancel()
		if err != nil {
			return fmt.Errorf("heain-sdk: certificate status of %s unavailable: %w", cert.Subject.CommonName, err)
		}
		st = certStatus{valid: out.Valid, at: time.Now()}
		a.certs.mu.Lock()
		a.certs.m[serial] = st
		a.certs.mu.Unlock()
	}
	if !st.valid {
		return fmt.Errorf("heain-sdk: %s (serial %s): %w", cert.Subject.CommonName, serial, ErrRevoked)
	}
	return nil
}
