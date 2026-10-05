package conformance

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"path/filepath"
	"strings"
	"time"
)

// PKI writes the harness certificates into dir/certs: a test root CA, one
// certificate per core node (SANs: node id, localhost, 127.0.0.1 and its
// harness IP), admin and approver-1, the provisioning intermediate CA
// (apps get their certificates only through the real provisioning flow),
// and a rogue CA with a look-alike app certificate (C2).
func PKI(dir string, nodes map[string]string) error {
	cd := filepath.Join(dir, "certs")
	ca, caKey, err := mkCert(nil, nil, "heain-conformance-ca", nil, nil, true, nil)
	if err != nil {
		return err
	}
	if err := save(cd, "ca", ca, caKey); err != nil {
		return err
	}
	for id, ip := range nodes {
		c, k, err := mkCert(ca, caKey, id, []string{id, "localhost"}, []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP(ip)}, false, nil)
		if err != nil {
			return err
		}
		if err := save(cd, id, c, k); err != nil {
			return err
		}
	}
	for _, id := range []string{"admin", "approver-1"} {
		c, k, err := mkCert(ca, caKey, id, []string{id}, nil, false, nil)
		if err != nil {
			return err
		}
		if err := save(cd, id, c, k); err != nil {
			return err
		}
	}
	prov, provKey, err := mkCert(ca, caKey, "heain-conformance-provisioning-ca", nil, nil, true, nil)
	if err != nil {
		return err
	}
	if err := save(cd, "prov", prov, provKey); err != nil {
		return err
	}
	rogue, rogueKey, err := mkCert(nil, nil, "rogue-ca", nil, nil, true, nil)
	if err != nil {
		return err
	}
	rc, rk, err := mkCert(rogue, rogueKey, "conformance-probe.p1", nil, nil, false, []string{"heain-sdk-client"})
	if err != nil {
		return err
	}
	if err := save(cd, "rogue-app", rc, rk); err != nil {
		return err
	}
	return writeShared(filepath.Join(dir, "topology.json"), []byte(`{"zones":{"zone-a":[]}}`), 0o644)
}

var serial int64 = time.Now().UnixNano() % 1e12

func mkCert(parent *x509.Certificate, parentKey *rsa.PrivateKey, cn string, dns []string, ips []net.IP, isCA bool, ou []string) (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	serial++
	t := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn, OrganizationalUnit: ou},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(30 * 24 * time.Hour), DNSNames: dns, IPAddresses: ips}
	if isCA {
		t.IsCA, t.BasicConstraintsValid = true, true
		t.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		t.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}
	signer, signKey := t, key
	if parent != nil {
		signer, signKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, t, signer, &key.PublicKey, signKey)
	if err != nil {
		return nil, nil, fmt.Errorf("pki %s: %w", cn, err)
	}
	c, err := x509.ParseCertificate(der)
	return c, key, err
}

func save(dir, name string, c *x509.Certificate, k *rsa.PrivateKey) error {
	cp := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	kp := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	if err := writeShared(filepath.Join(dir, name+".pem"), cp, 0o644); err != nil {
		return err
	}
	return writeShared(filepath.Join(dir, name+".key"), kp, 0o600)
}

// ParseNodes reads "G=10.77.0.10,W=10.77.0.12".
func ParseNodes(s string) map[string]string {
	out := map[string]string{}
	for _, p := range strings.Split(s, ",") {
		if id, ip, ok := strings.Cut(strings.TrimSpace(p), "="); ok {
			out[id] = ip
		}
	}
	return out
}
