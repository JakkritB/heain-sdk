package heain

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
)

func verifySig(rec Record, cert *tls.Certificate) error {
	sig, err := base64.StdEncoding.DecodeString(rec.Signature)
	if err != nil {
		return err
	}
	rec.Signature = ""
	canon, err := Canonical(rec)
	if err != nil {
		return err
	}
	h := sha256.Sum256(canon)
	leaf := cert.Leaf
	if leaf == nil {
		if leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return err
		}
	}
	switch k := leaf.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, h[:], sig) {
			return errors.New("signature does not verify")
		}
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(k, crypto.SHA256, h[:], sig)
	default:
		return errors.New("unsupported key type")
	}
	return nil
}
