// Package zonesync is the network side of keeping an app's data the same on
// every node of its zone (Stage B, author decisions 2026-10-08: sync inside a
// zone, ciphertext only; heain-database first, then heain-gateway).
//
// The app seals its data under a zone key (heain.App.ZoneKey), so a record
// and its blinded key are the same bytes on every node and can be copied
// without being opened. The app keeps a change log (Log, its own storage);
// every instance serves its log (Handler) and pulls the logs of the other
// instances of the zone (Puller), found with zone discovery only, so nothing
// crosses a zone. Newer wins: by the write's time, then its origin.
//
// A Poke asks every other instance to pull now (a revocation should not
// wait for the next round).
package zonesync

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/heainframework/heain-sdk/heain"
)

// Change is one write in a change log.
type Change struct {
	Seq    uint64 `json:"seq"`
	Store  string `json:"store"`
	Key    string `json:"key"`             // blinded
	Value  []byte `json:"value,omitempty"` // sealed; nil = deleted
	TS     int64  `json:"ts"`              // unix nanoseconds of the write
	Origin string `json:"origin"`          // the log that wrote it first
}

// NewerThan reports whether c wins over a write made at ts by origin.
func (c Change) NewerThan(ts int64, origin string) bool {
	return c.TS > ts || (c.TS == ts && c.Origin > origin)
}

// Log is an app's change log.
type Log interface {
	// Epoch identifies the log (a new one on every recreation).
	Epoch() string
	// Changes returns up to limit changes after since, and the head.
	Changes(since uint64, limit int) (epoch string, head uint64, cs []Change, err error)
	// Last is the epoch and sequence last read from peer.
	Last(peer string) (epoch string, seq uint64)
	// Apply applies changes read from peer's log and moves its cursor;
	// it returns how many were newer than what is held here.
	Apply(peer, epoch string, cs []Change) (int, error)
}

// Page is one answer of a change log.
type Page struct {
	Epoch   string   `json:"epoch"`
	Head    uint64   `json:"head"`
	Changes []Change `json:"changes"`
}

// SameApp reports whether the caller of r is another instance of app.
func SameApp(app *heain.App, r *http.Request) bool {
	return strings.HasPrefix(heain.Caller(r.Context()), app.Manifest.App.ID+".")
}

func fail(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":{"code":"` + code + `","message":"` + msg + `","retryable":false}}`))
}

// Handler serves GET <path>?since=&limit= (the log) to other instances of
// the same app only.
func Handler(app *heain.App, l Log) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !SameApp(app, r) {
			fail(w, http.StatusForbidden, "forbidden", "only another instance of "+app.Manifest.App.ID+" may read the change log")
			return
		}
		since, _ := strconv.ParseUint(r.URL.Query().Get("since"), 10, 64)
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		ep, head, cs, err := l.Changes(since, limit)
		if err != nil {
			fail(w, http.StatusInternalServerError, "internal", "change log unavailable")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = jsonEncode(w, Page{Epoch: ep, Head: head, Changes: cs})
	}
}

// Puller reads the other instances' logs.
type Puller struct {
	App        *heain.App
	Log        Log
	Capability string // the capability of the log endpoint (version 1)
	Path       string // the log endpoint, e.g. /v1/replica/changes
	PokePath   string // optional: POST endpoint that makes an instance pull now
	// Audit, when set, is called with the capability, peer and count after
	// changes from a peer were applied.
	Audit func(ctx context.Context, peer string, applied int)
	Logf  func(string, ...any)

	mu   sync.Mutex
	kick chan struct{}
}

const pageSize = 500

func (p *Puller) logf(f string, v ...any) {
	if p.Logf != nil {
		p.Logf(f, v...)
	}
}

// Once reads every peer's new changes once; it returns how many were
// applied and from how many peers a log was read to its end.
func (p *Puller) Once(ctx context.Context) (int, int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	insts, _, err := p.App.DiscoverZone(ctx, p.Capability, 1)
	if err != nil {
		return 0, 0, err
	}
	total, read := 0, 0
	for _, in := range insts {
		if in.AppID != p.App.Manifest.App.ID || in.EndpointBase == "" {
			continue
		}
		peer := in.Node + "/" + in.InstanceID
		ep, since := p.Log.Last(peer)
		applied := 0
		for {
			var page Page
			_, err := p.App.Call(ctx, heain.CallSpec{App: in.AppID, Capability: p.Capability, Version: 1, Instance: in.InstanceID,
				Scope: heain.ScopeZone, Method: http.MethodGet,
				Path: p.Path + "?since=" + strconv.FormatUint(since, 10) + "&limit=" + strconv.Itoa(pageSize),
				Out:  &page, Timeout: 30 * time.Second})
			if err != nil {
				p.logf("zonesync: from %s: %v", peer, err)
				break
			}
			if page.Epoch == p.Log.Epoch() {
				break // this very instance
			}
			if page.Epoch != ep && since != 0 {
				ep, since = page.Epoch, 0 // the peer's log was recreated: from the start
				continue
			}
			ep = page.Epoch
			n, err := p.Log.Apply(peer, page.Epoch, page.Changes)
			applied += n
			if err != nil {
				p.logf("zonesync: from %s: %v", peer, err)
				break
			}
			if len(page.Changes) < pageSize {
				read++
				break
			}
			since = page.Changes[len(page.Changes)-1].Seq
		}
		if applied > 0 && p.Audit != nil {
			p.Audit(ctx, peer, applied)
		}
		total += applied
	}
	return total, read, nil
}

// Run pulls every every (and at once after a Kick) until ctx ends.
func (p *Puller) Run(ctx context.Context, every time.Duration) {
	p.mu.Lock()
	if p.kick == nil {
		p.kick = make(chan struct{}, 1)
	}
	kick := p.kick
	p.mu.Unlock()
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		case <-kick:
		}
		if n, peers, err := p.Once(ctx); err != nil {
			p.logf("zonesync: %v", err)
		} else if n > 0 {
			p.logf("zonesync: %d change(s) applied from %d peer(s)", n, peers)
		}
	}
}

// Kick makes Run pull now.
func (p *Puller) Kick() {
	p.mu.Lock()
	if p.kick == nil {
		p.kick = make(chan struct{}, 1)
	}
	k := p.kick
	p.mu.Unlock()
	select {
	case k <- struct{}{}:
	default:
	}
}

// PokeHandler serves POST <PokePath>: another instance of the app asks
// this one to pull now.
func (p *Puller) PokeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !SameApp(p.App, r) {
			fail(w, http.StatusForbidden, "forbidden", "only another instance of "+p.App.Manifest.App.ID+" may ask")
			return
		}
		p.Kick()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"pulling":true}`))
	}
}

// Poke asks every other instance of the zone to pull now; it returns how
// many answered. Instances that cannot be reached pull at their next round.
func (p *Puller) Poke(ctx context.Context) int {
	if p.PokePath == "" {
		return 0
	}
	insts, _, err := p.App.DiscoverZone(ctx, p.Capability, 1)
	if err != nil {
		return 0
	}
	n := 0
	for _, in := range insts {
		if in.AppID != p.App.Manifest.App.ID || in.EndpointBase == "" {
			continue
		}
		if _, err := p.App.Call(ctx, heain.CallSpec{App: in.AppID, Capability: p.Capability, Version: 1, Instance: in.InstanceID,
			Scope: heain.ScopeZone, Method: http.MethodPost, Path: p.PokePath, Timeout: 5 * time.Second}); err == nil {
			n++
		}
	}
	return n
}
