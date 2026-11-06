package custody

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

// The holder decrypts its share and encrypts it to the node for one grant;
// the node opens it only with that grant's label (heain-core C12's labels).
func TestRelease(t *testing.T) {
	holder, _ := rsa.GenerateKey(rand.Reader, 2048)
	node, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyID := "seal/z-b1-1/mpapp.ob1/vote/ballots/b1-1.const"
	part := []byte{3, 9, 9, 9}
	enc, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &holder.PublicKey, part, []byte("heain-seal-share|"+keyID))
	if err != nil {
		t.Fatal(err)
	}
	s := Share{KeyID: keyID, X: 3, EncB64: base64.StdEncoding.EncodeToString(enc)}
	r, err := Release(holder, &node.PublicKey, "g-1", s)
	if err != nil {
		t.Fatal(err)
	}
	ct, _ := base64.StdEncoding.DecodeString(r.EncB64)
	got, err := rsa.DecryptOAEP(sha256.New(), nil, node, ct, []byte("heain-seal-release|g-1|"+keyID))
	if err != nil || string(got) != string(part) {
		t.Fatalf("node: %v %v", got, err)
	}
	if _, err := rsa.DecryptOAEP(sha256.New(), nil, node, ct, ReleaseLabel("g-2", keyID)); err == nil {
		t.Fatal("a share released for one grant opened for another")
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := Release(other, &node.PublicKey, "g-1", s); err == nil {
		t.Fatal("another holder released this share")
	}
	s.X = 4
	if _, err := Release(holder, &node.PublicKey, "g-1", s); err == nil {
		t.Fatal("a share that does not match its listing was released")
	}
}
