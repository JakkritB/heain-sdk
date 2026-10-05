package heain

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// Independent audit (core v1.3 step 4c-1): an app listed in the node's
// audit.readers policy (heain-audit) reads the node's audit chain with its
// hashes and ciphertext, verifies it itself and keeps its own copy.

// AuditEvent is one core audit event (decrypted).
type AuditEvent struct {
	Timestamp time.Time      `json:"Timestamp"`
	Actor     string         `json:"Actor"`
	Action    string         `json:"Action"`
	Category  string         `json:"Category"`
	Result    string         `json:"Result"`
	Detail    map[string]any `json:"Detail"`
}

// AuditRecord is one link of the chain:
// Hash = SHA-256(PrevHash || seq_be64 || Ciphertext).
type AuditRecord struct {
	Seq        uint64     `json:"seq"`
	PrevHash   string     `json:"prev_hash"`
	Hash       string     `json:"hash"`
	Ciphertext []byte     `json:"ciphertext_b64"`
	Event      AuditEvent `json:"event"`
}

// AuditPage is one read of the chain and the node's head at that moment.
type AuditPage struct {
	Records []AuditRecord `json:"records"`
	Head    struct {
		Seq  uint64 `json:"seq"`
		Hash string `json:"hash"`
	} `json:"head"`
}

// AuditRecords reads up to limit records from sequence from (1-based;
// core caps limit at 500). Core answers 403 audit_reader_not_allowed
// unless this app is in its audit.readers policy.
func (a *App) AuditRecords(ctx context.Context, from uint64, limit int) (AuditPage, error) {
	var p AuditPage
	_, err := a.Core.Do(ctx, http.MethodGet, fmt.Sprintf("/v1/app/audit/records?from=%d&limit=%d", from, limit), nil, nil, &p)
	return p, err
}

// AuditChainHash is core's chain link: SHA-256(prev || seq_be64 || ciphertext).
func AuditChainHash(prev []byte, seq uint64, ciphertext []byte) []byte {
	h := sha256.New()
	h.Write(prev)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], seq)
	h.Write(b[:])
	h.Write(ciphertext)
	return h.Sum(nil)
}

// ErrAuditChain: a record does not link to the previous one.
var ErrAuditChain = errors.New("heain-sdk: audit chain does not verify")

// VerifyAuditRecords checks that recs follow prevHash (hex; "" or 64
// zeros for genesis) and each other, recomputing every hash. It returns
// the hash of the last record.
func VerifyAuditRecords(prevHash string, recs []AuditRecord) (string, error) {
	prev, err := hex.DecodeString(prevHash)
	if err != nil || (len(prev) != 0 && len(prev) != sha256.Size) {
		return "", fmt.Errorf("%w: bad previous hash", ErrAuditChain)
	}
	if len(prev) == 0 {
		prev = make([]byte, sha256.Size)
	}
	for _, r := range recs {
		if r.PrevHash != hex.EncodeToString(prev) {
			return "", fmt.Errorf("%w: seq %d does not follow the previous record", ErrAuditChain, r.Seq)
		}
		h := AuditChainHash(prev, r.Seq, r.Ciphertext)
		if r.Hash != hex.EncodeToString(h) {
			return "", fmt.Errorf("%w: seq %d content does not match its hash", ErrAuditChain, r.Seq)
		}
		prev = h
	}
	return hex.EncodeToString(prev), nil
}

// SignDigest signs a SHA-256 digest with the app key (ECDSA ASN.1 or RSA
// PKCS#1 v1.5), e.g. a checkpoint root; verify with VerifyDigest and
// CertificatePEM.
func (a *App) SignDigest(digest []byte) ([]byte, error) {
	if len(digest) != sha256.Size {
		return nil, errors.New("heain-sdk: SignDigest needs a SHA-256 digest")
	}
	s, ok := a.key.(crypto.Signer)
	if !ok {
		return nil, errors.New("heain-sdk: the app key cannot sign")
	}
	return s.Sign(rand.Reader, digest, crypto.SHA256)
}

// CertificatePEM is the app certificate (leaf) that SignDigest's
// signatures verify against.
func (a *App) CertificatePEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.pair.Certificate[0]})
}

// VerifyDigest checks a SignDigest signature against a PEM certificate.
func VerifyDigest(certPEM, digest, sig []byte) error {
	b, _ := pem.Decode(certPEM)
	if b == nil {
		return errors.New("heain-sdk: no certificate")
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return err
	}
	switch k := c.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, digest, sig) {
			return errors.New("heain-sdk: signature does not verify")
		}
		return nil
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(k, crypto.SHA256, digest, sig)
	}
	return errors.New("heain-sdk: unsupported key type")
}
