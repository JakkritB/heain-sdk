package core

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

type pkiT struct {
	root, ica *x509.Certificate
	rk, ik    *rsa.PrivateKey
	pool      *x509.CertPool
	n         int64
}

func newPKIT(t *testing.T) *pkiT {
	p := &pkiT{}
	p.rk, _ = rsa.GenerateKey(rand.Reader, 2048)
	p.ik, _ = rsa.GenerateKey(rand.Reader, 2048)
	p.root = p.mk(t, &x509.Certificate{Subject: pkix.Name{CommonName: "root"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(48 * time.Hour)}, nil, &p.rk.PublicKey, p.rk)
	p.ica = p.mk(t, &x509.Certificate{Subject: pkix.Name{CommonName: "node-ca", OrganizationalUnit: []string{"heain-node-ca"}}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(48 * time.Hour)},
		p.root, &p.ik.PublicKey, p.rk)
	p.pool = x509.NewCertPool()
	p.pool.AddCert(p.root)
	return p
}

func (p *pkiT) mk(t *testing.T, tpl, parent *x509.Certificate, pub *rsa.PublicKey, signer *rsa.PrivateKey) *x509.Certificate {
	t.Helper()
	p.n++
	tpl.SerialNumber = big.NewInt(p.n)
	if parent == nil {
		parent = tpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func (p *pkiT) leaf(t *testing.T, name, ou string, notAfter time.Time) *x509.Certificate {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	return p.mk(t, &x509.Certificate{Subject: pkix.Name{CommonName: name, OrganizationalUnit: []string{ou}}, DNSNames: []string{name},
		NotBefore: notAfter.Add(-time.Hour), NotAfter: notAfter, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}},
		p.ica, &k.PublicKey, p.ik)
}

// heain-core C2: core's short-lived certificate expired while its zone is cut
// off is accepted only within the tolerance core gave, and nothing else is relaxed.
func TestVerifyCoreExpired(t *testing.T) {
	p := newPKIT(t)
	now := time.Now()
	valid := p.leaf(t, "z-ls-1", NodeCertOU, now.Add(time.Hour))
	expired := p.leaf(t, "z-ls-1", NodeCertOU, now.Add(-10*time.Minute))
	installed := p.leaf(t, "z-ls-1", "other", now.Add(-10*time.Minute))
	var told []time.Time
	note := func(at time.Time) { told = append(told, at) }
	if err := VerifyCore([]*x509.Certificate{valid, p.ica}, p.pool, "z-ls-1", now, 0, note); err != nil {
		t.Fatalf("a valid certificate: %v", err)
	}
	if err := VerifyCore([]*x509.Certificate{valid, p.ica}, p.pool, "z-ls-2", now, time.Hour, note); err == nil {
		t.Fatal("another node's name accepted")
	}
	if err := VerifyCore([]*x509.Certificate{expired, p.ica}, p.pool, "z-ls-1", now, 0, note); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired without a tolerance: %v", err)
	}
	if err := VerifyCore([]*x509.Certificate{expired, p.ica}, p.pool, "z-ls-1", now, 5*time.Minute, note); err == nil {
		t.Fatal("expired longer ago than the tolerance accepted")
	}
	if err := VerifyCore([]*x509.Certificate{expired, p.ica}, p.pool, "z-ls-1", now, time.Hour, note); err != nil || len(told) != 1 {
		t.Fatalf("expired within the tolerance: %v (told %d)", err, len(told))
	}
	if err := VerifyCore([]*x509.Certificate{installed, p.ica}, p.pool, "z-ls-1", now, time.Hour, note); err == nil {
		t.Fatal("an expired certificate that is not a short-lived node certificate accepted")
	}
	if err := VerifyCore([]*x509.Certificate{expired, p.ica}, p.pool, "", now, time.Hour, note); err == nil {
		t.Fatal("no name")
	}
	other := newPKIT(t)
	if err := VerifyCore([]*x509.Certificate{expired, p.ica}, other.pool, "z-ls-1", now, time.Hour, note); err == nil {
		t.Fatal("another deployment's certificate accepted")
	}
}
