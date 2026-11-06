// Package custody is the custodian's side of heain-core's sealed data with
// custodians (core C12, heain-sdk 1.6): records a policy seals under a key
// whose private part is split k of n among holders open only when k of them
// take part. A holder's share is encrypted to its own certificate key; this
// package decrypts it on the holder's machine, encrypts it again to the node
// it is talking to, bound to one grant, and sends it -- the holder's private
// key never leaves its machine, and a share sent for one grant opens nothing
// under another.
package custody

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func shareLabel(keyID string) []byte { return []byte("heain-seal-share|" + keyID) }

// ReleaseLabel binds a share sent to a node to one grant and key (the same
// label heain-core uses).
func ReleaseLabel(grant, keyID string) []byte {
	return []byte("heain-seal-release|" + grant + "|" + keyID)
}

// Share is one of the holder's shares as the node lists it.
type Share struct {
	KeyID  string `json:"key_id"`
	X      byte   `json:"x"`
	EncB64 string `json:"enc_b64"`
}

// Released is a share encrypted to the node for a grant.
type Released struct {
	KeyID  string `json:"key_id"`
	EncB64 string `json:"enc_b64"`
}

// Release decrypts the holder's share with its key and encrypts it to the
// node's key, bound to grant.
func Release(holderKey *rsa.PrivateKey, nodeKey *rsa.PublicKey, grant string, s Share) (Released, error) {
	enc, err := base64.StdEncoding.DecodeString(s.EncB64)
	if err != nil {
		return Released{}, err
	}
	part, err := rsa.DecryptOAEP(sha256.New(), nil, holderKey, enc, shareLabel(s.KeyID))
	if err != nil {
		return Released{}, fmt.Errorf("custody: %s: not a share of this holder", s.KeyID)
	}
	defer func() {
		for i := range part {
			part[i] = 0
		}
	}()
	if len(part) < 2 || part[0] != s.X {
		return Released{}, fmt.Errorf("custody: %s: the share does not match its listing", s.KeyID)
	}
	out, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, nodeKey, part, ReleaseLabel(grant, s.KeyID))
	if err != nil {
		return Released{}, err
	}
	return Released{KeyID: s.KeyID, EncB64: base64.StdEncoding.EncodeToString(out)}, nil
}

// Client is a holder talking to one heain-core node with its certificate.
type Client struct {
	Base string
	HTTP *http.Client
	Key  *rsa.PrivateKey
}

// New makes a holder's client: base is the node's admin URL, serverName the
// node's name in its certificate.
func New(base, certFile, keyFile, caFile, serverName string) (*Client, error) {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	k, ok := pair.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("custody: the holder's key must be RSA")
	}
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("custody: the CA file holds no certificate")
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, RootCAs: pool, ServerName: serverName}
	return &Client{Base: strings.TrimSuffix(base, "/"), Key: k,
		HTTP: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: tc, Proxy: nil}}}, nil
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode/100 != 2 {
		return resp, fmt.Errorf("custody: %s %s: %d %s", method, path, resp.StatusCode, bytes.TrimSpace(raw))
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp, err
		}
	}
	return resp, nil
}

// Result is what one holder's part in a grant came to.
type Result struct {
	Grant         string         `json:"grant"`
	Holder        string         `json:"holder"`
	Sent          int            `json:"sent"`
	HoldersPerKey map[string]int `json:"holders_per_key"`
	Approved      bool           `json:"approved"`
}

// TakePart reads this holder's shares of the keys grant covers from the
// node, releases each to that node (its key is the one on the TLS
// connection: the node itself), sends them, and approves the grant when
// approve is set (the holder's P5 approval).
func (c *Client) TakePart(ctx context.Context, grant string, approve bool) (Result, error) {
	var list struct {
		Holder string  `json:"holder"`
		Shares []Share `json:"shares"`
	}
	resp, err := c.do(ctx, http.MethodGet, "/v1/admin/sealed/custody?grant="+url.QueryEscape(grant), nil, &list)
	if err != nil {
		return Result{}, err
	}
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return Result{}, errors.New("custody: no node certificate on the connection")
	}
	nodeKey, ok := resp.TLS.PeerCertificates[0].PublicKey.(*rsa.PublicKey)
	if !ok {
		return Result{}, errors.New("custody: the node's key is not RSA")
	}
	if len(list.Shares) == 0 {
		return Result{}, errors.New("custody: the node lists no share of this holder for the grant")
	}
	body := struct {
		Grant  string     `json:"grant"`
		Shares []Released `json:"shares"`
	}{Grant: grant}
	for _, s := range list.Shares {
		r, err := Release(c.Key, nodeKey, grant, s)
		if err != nil {
			return Result{}, err
		}
		body.Shares = append(body.Shares, r)
	}
	res := Result{Grant: grant, Holder: list.Holder}
	var sent struct {
		Received      int            `json:"received"`
		HoldersPerKey map[string]int `json:"holders_per_key"`
	}
	if _, err := c.do(ctx, http.MethodPost, "/v1/admin/sealed/custody", body, &sent); err != nil {
		return res, err
	}
	res.Sent, res.HoldersPerKey = sent.Received, sent.HoldersPerKey
	if approve {
		if _, err := c.do(ctx, http.MethodPost, "/v1/admin/policy/"+url.PathEscape(grant)+"/approve", nil, nil); err != nil {
			return res, err
		}
		res.Approved = true
	}
	return res, nil
}
