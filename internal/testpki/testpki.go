// Package testpki makes a throwaway CA and certificates for the SDK's tests.
package testpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// PKI is a CA plus helpers to issue leaf certificates into Dir.
type PKI struct {
	Dir    string
	CAFile string
	ca     *x509.Certificate
	caKey  *ecdsa.PrivateKey
	serial int64
}

func New(t *testing.T) *PKI {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	p := &PKI{Dir: t.TempDir(), ca: ca, caKey: key, serial: 1}
	p.CAFile = filepath.Join(p.Dir, "ca.pem")
	_ = os.WriteFile(p.CAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	return p
}

// Issue writes <name>.pem/<name>.key for CN cn (and SAN cn, localhost,
// 127.0.0.1) and returns the files and the TLS pair.
func (p *PKI) Issue(t *testing.T, name, cn string) (certFile, keyFile string, pair tls.Certificate) {
	t.Helper()
	p.serial++
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(p.serial), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), DNSNames: []string{cn, "localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
	certFile, keyFile = filepath.Join(p.Dir, name+".pem"), filepath.Join(p.Dir, name+".key")
	_ = os.WriteFile(certFile, certPEM, 0o644)
	_ = os.WriteFile(keyFile, keyPEM, 0o600)
	pair, _ = tls.X509KeyPair(certPEM, keyPEM)
	return
}

// IssueApp issues an app certificate as core's provisioning does: CN
// <app-id>.<instance-id>, OU heain-sdk-client, client-auth only, no SANs.
func (p *PKI) IssueApp(t *testing.T, name, cn string) (certFile, keyFile string, pair tls.Certificate) {
	t.Helper()
	p.serial++
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(p.serial), Subject: pkix.Name{CommonName: cn, OrganizationalUnit: []string{"heain-sdk-client"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
	certFile, keyFile = filepath.Join(p.Dir, name+".pem"), filepath.Join(p.Dir, name+".key")
	_ = os.WriteFile(certFile, certPEM, 0o644)
	_ = os.WriteFile(keyFile, keyPEM, 0o600)
	pair, _ = tls.X509KeyPair(certPEM, keyPEM)
	return
}

// Pool is the CA as a cert pool.
func (p *PKI) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.ca)
	return pool
}
