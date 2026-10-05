package heain

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
)

type ctxKey int

const (
	keyTrace ctxKey = iota
	keyLane
	keyCaller
	keyRecords
)

// Header names of the App API's direct calls (spec 01 §3, 02 §8).
const (
	HeaderTrace = "X-Heain-Trace"
	HeaderLane  = "X-Heain-Lane"
)

// TraceID is the formal process this request or call belongs to.
func TraceID(ctx context.Context) string { s, _ := ctx.Value(keyTrace).(string); return s }

// Lane is the lane of the capability being served ("" = none).
func Lane(ctx context.Context) string { s, _ := ctx.Value(keyLane).(string); return s }

// Caller is the calling app instance (<app-id>.<instance-id>) of a direct call.
func Caller(ctx context.Context) string { s, _ := ctx.Value(keyCaller).(string); return s }

// WithTrace starts (or continues) a formal process in ctx.
func WithTrace(ctx context.Context, traceID, lane string) context.Context {
	if traceID == "" {
		traceID = NewID()
	}
	return context.WithValue(context.WithValue(ctx, keyTrace, traceID), keyLane, lane)
}

type recordSink struct {
	mu  sync.Mutex
	ids []string
}

func (r *recordSink) add(id string) {
	r.mu.Lock()
	r.ids = append(r.ids, id)
	r.mu.Unlock()
}

func (r *recordSink) list() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.ids...)
}

// NewID is a random UUID v4.
func NewID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
