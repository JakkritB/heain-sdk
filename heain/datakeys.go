package heain

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
)

// Data keys (core v1.3 step 4b-1): formal data an app persists must be
// encrypted at rest (spec 00 §3, data_classes[].encrypted_at_rest). The key
// lives in core's durable KMS on this node; the app holds a copy in memory
// only. Destroying it in core (DestroyDataKey) is the crypto-shred of
// everything sealed under it.

type dataKeys struct {
	mu   sync.Mutex
	keys map[string][]byte
	zone map[string]zoneKeyEntry // zone.go
}

// DataKey returns the app's 256-bit data key name (created in core's KMS
// on first use; every instance of this app on the node gets the same key).
// The key is cached in memory; never write it to disk.
func (a *App) DataKey(ctx context.Context, name string) ([]byte, error) {
	a.dk.mu.Lock()
	defer a.dk.mu.Unlock()
	if k, ok := a.dk.keys[name]; ok {
		return k, nil
	}
	var out struct {
		Key []byte `json:"key_b64"`
	}
	if _, err := a.Core.Do(ctx, http.MethodPost, "/v1/app/keys", nil, map[string]any{"name": name}, &out); err != nil {
		return nil, err
	}
	if len(out.Key) != 32 {
		return nil, fmt.Errorf("heain-sdk: data key %s: core returned %d bytes", name, len(out.Key))
	}
	if a.dk.keys == nil {
		a.dk.keys = map[string][]byte{}
	}
	a.dk.keys[name] = out.Key
	return out.Key, nil
}

// Sealer returns a Sealer over the data key name.
func (a *App) Sealer(ctx context.Context, name string) (*Sealer, error) {
	k, err := a.DataKey(ctx, name)
	if err != nil {
		return nil, err
	}
	return NewSealer(k)
}

// DestroyDataKey crypto-shreds data key name in core and wipes the cached
// copy. Data sealed under it can never be opened again; drop any Sealer
// made from it. A later DataKey(name) creates a new, different key.
func (a *App) DestroyDataKey(ctx context.Context, name string) error {
	if _, err := a.Core.Do(ctx, http.MethodDelete, "/v1/app/keys/"+url.PathEscape(name), nil, nil, nil); err != nil {
		return err
	}
	a.dk.mu.Lock()
	defer a.dk.mu.Unlock()
	if k, ok := a.dk.keys[name]; ok {
		wipe(k)
		delete(a.dk.keys, name)
	}
	return nil
}

// Sealer is AES-256-GCM with a random nonce: Seal returns nonce||ciphertext.
// aad binds a sealed value to its place (e.g. bucket and key), so it cannot
// be moved to another record unnoticed.
type Sealer struct{ aead cipher.AEAD }

// ErrOpen is returned for data that was not sealed by this key and aad.
var ErrOpen = errors.New("heain-sdk: sealed data cannot be opened (wrong key, wrong aad or tampered)")

// NewSealer makes a Sealer from a 32-byte key.
func NewSealer(key []byte) (*Sealer, error) {
	if len(key) != 32 {
		return nil, errors.New("heain-sdk: a sealer needs a 32-byte key")
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: g}, nil
}

// Seal encrypts plaintext bound to aad.
func (s *Sealer) Seal(plaintext, aad []byte) []byte {
	nonce := make([]byte, s.aead.NonceSize(), s.aead.NonceSize()+len(plaintext)+s.aead.Overhead())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic("heain-sdk: no randomness: " + err.Error())
	}
	return s.aead.Seal(nonce, nonce, plaintext, aad)
}

// Open decrypts what Seal returned for the same aad.
func (s *Sealer) Open(sealed, aad []byte) ([]byte, error) {
	n := s.aead.NonceSize()
	if len(sealed) < n+s.aead.Overhead() {
		return nil, ErrOpen
	}
	p, err := s.aead.Open(nil, sealed[:n], sealed[n:], aad)
	if err != nil {
		return nil, ErrOpen
	}
	return p, nil
}
