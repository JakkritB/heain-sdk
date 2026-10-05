// Package provision obtains an app certificate through heain-core's
// provisioning flow (spec 05 C3: never a pre-made certificate):
// token + bootstrap credential -> CSR -> certificate on probation ->
// confirm.
package provision

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/heainframework/heain-sdk/core"
)

// Request is what an operator hands an app instance to enroll it.
type Request struct {
	CoreURL, CoreNodeID string
	CAFile              string // deployment root CA
	ChainFile           string // provisioning intermediate CA certificate (appended to the issued cert)
	Token               string // one-time token from POST /provision/token (admin)
	BootstrapCertPEM    string // bootstrap credential issued with the token
	BootstrapKeyPEM     string
	AppID, InstanceID   string
	// OutDir receives app.pem (certificate + chain) and app.key (0600).
	OutDir string
}

// Result names the files written.
type Result struct{ CertFile, KeyFile, Serial string }

// Enroll runs the whole flow and writes the certificate and key.
func Enroll(ctx context.Context, r Request) (Result, error) {
	chain, err := os.ReadFile(r.ChainFile)
	if err != nil {
		return Result{}, fmt.Errorf("provision: chain: %w", err)
	}
	pool, err := core.LoadPool(r.CAFile)
	if err != nil {
		return Result{}, err
	}
	boot, err := tls.X509KeyPair([]byte(r.BootstrapCertPEM+"\n"+string(chain)), []byte(r.BootstrapKeyPEM))
	if err != nil {
		return Result{}, fmt.Errorf("provision: bootstrap credential: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Result{}, err
	}
	cn := r.AppID + "." + r.InstanceID
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		return Result{}, err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	hc := func(c tls.Certificate) *http.Client {
		return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{c}, RootCAs: pool, ServerName: r.CoreNodeID}}}
	}
	base := strings.TrimSuffix(r.CoreURL, "/")
	body, _ := json.Marshal(map[string]string{"token": r.Token, "csr_pem": string(csrPEM)})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, base+"/provision/csr", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc(boot).Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("provision/csr: %w", err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("provision/csr: %d %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var out struct {
		CertPEM string `json:"cert_pem"`
		Serial  string `json:"serial"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return Result{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return Result{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPEM := strings.TrimSpace(out.CertPEM) + "\n" + string(chain)
	app, err := tls.X509KeyPair([]byte(certPEM), keyPEM)
	if err != nil {
		return Result{}, fmt.Errorf("provision: issued certificate: %w", err)
	}
	// Confirm with the new certificate to end its probation.
	creq, _ := http.NewRequestWithContext(ctx, http.MethodPost, base+"/provision/confirm", bytes.NewReader([]byte("{}")))
	cresp, err := hc(app).Do(creq)
	if err != nil {
		return Result{}, fmt.Errorf("provision/confirm: %w", err)
	}
	cdata, _ := io.ReadAll(cresp.Body)
	cresp.Body.Close()
	if cresp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("provision/confirm: %d %s", cresp.StatusCode, strings.TrimSpace(string(cdata)))
	}
	if err := os.MkdirAll(r.OutDir, 0o700); err != nil {
		return Result{}, err
	}
	res := Result{CertFile: filepath.Join(r.OutDir, "app.pem"), KeyFile: filepath.Join(r.OutDir, "app.key"), Serial: out.Serial}
	if err := os.WriteFile(res.KeyFile, keyPEM, 0o600); err != nil {
		return Result{}, err
	}
	if err := os.WriteFile(res.CertFile, []byte(certPEM), 0o644); err != nil {
		return Result{}, err
	}
	return res, nil
}
