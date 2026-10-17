package heain

import (
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

// heain-core C3: a pruned record (content deleted, link kept) still links;
// a pruned record whose hash is not the one its successor follows does not.
func TestVerifyPrunedRecords(t *testing.T) {
	prev := make([]byte, 32)
	var recs []AuditRecord
	for i := uint64(1); i <= 4; i++ {
		ct := []byte(fmt.Sprintf("ciphertext-%d", i))
		h := AuditChainHash(prev, i, ct)
		recs = append(recs, AuditRecord{Seq: i, PrevHash: hex.EncodeToString(prev), Hash: hex.EncodeToString(h), Ciphertext: ct})
		prev = h
	}
	recs[1].Ciphertext, recs[1].Pruned = nil, true
	if last, err := VerifyAuditRecords("", recs); err != nil || last != hex.EncodeToString(prev) {
		t.Fatalf("pruned record: %v", err)
	}
	recs[1].Hash = "00" + recs[1].Hash[2:]
	if _, err := VerifyAuditRecords("", recs); !errors.Is(err, ErrAuditChain) {
		t.Fatal("a pruned record with another hash must fail")
	}
	recs[1].Pruned = false
	if _, err := VerifyAuditRecords("", recs); !errors.Is(err, ErrAuditChain) {
		t.Fatal("a record without content that is not marked pruned must fail")
	}
}
