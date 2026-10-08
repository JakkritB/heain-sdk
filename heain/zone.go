package heain

// Zone scope (Stage B, author decisions 2026-10-08): an app whose manifest
// declares a data class wider than node-local may share data with its own
// instances on the other nodes of its zone (a Master's farm), never across
// zones (P7).
//
//   - ZoneKey is a data key every node of the zone holds (core wraps it to
//     each node's certificate key); a node cut off from its Master keeps it.
//   - DestroyZoneKey crypto-shreds it on the custodian (the zone's Master)
//     and, through tombstones, on every node of the zone.
//   - DiscoverZone finds instances on every node of the zone; CallSpec.Scope
//     "zone" makes Call use it.

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// ScopeZone is the zone scope of keys, discovery and calls.
const ScopeZone = "zone"

// ZoneKeyTTL is how long a zone key stays cached in this process: a
// destroy made on another node of the zone reaches this process within it.
var ZoneKeyTTL = 60 * time.Second

// ZoneInstance is an instance found in the zone and the node it runs on.
type ZoneInstance struct {
	Instance
	Node string `json:"node"`
}

type zoneKeyEntry struct {
	key []byte
	at  time.Time
}

// ZoneKey returns the app's zone data key name, made by the zone's
// custodian on first use. Every instance of this app on every node of the
// zone gets the same key. Core answers 503 zone_unavailable when this node
// holds no copy yet and cannot reach its Master.
func (a *App) ZoneKey(ctx context.Context, name string) ([]byte, error) {
	a.dk.mu.Lock()
	defer a.dk.mu.Unlock()
	if e, ok := a.dk.zone[name]; ok && time.Since(e.at) < ZoneKeyTTL {
		return e.key, nil
	}
	var out struct {
		Key []byte `json:"key_b64"`
	}
	if _, err := a.Core.Do(ctx, http.MethodPost, "/v1/app/keys", nil, map[string]any{"name": name, "scope": ScopeZone}, &out); err != nil {
		if e, ok := a.dk.zone[name]; ok {
			wipe(e.key)
			delete(a.dk.zone, name)
		}
		return nil, err
	}
	if len(out.Key) != 32 {
		return nil, fmt.Errorf("heain-sdk: zone key %s: core returned %d bytes", name, len(out.Key))
	}
	if a.dk.zone == nil {
		a.dk.zone = map[string]zoneKeyEntry{}
	}
	if e, ok := a.dk.zone[name]; ok && string(e.key) != string(out.Key) {
		wipe(e.key)
	}
	a.dk.zone[name] = zoneKeyEntry{key: out.Key, at: time.Now()}
	return out.Key, nil
}

// ZoneSealer returns a Sealer over the zone key name.
func (a *App) ZoneSealer(ctx context.Context, name string) (*Sealer, error) {
	k, err := a.ZoneKey(ctx, name)
	if err != nil {
		return nil, err
	}
	return NewSealer(k)
}

// DestroyZoneKey crypto-shreds the zone key name on the custodian and on
// this node; the other nodes of the zone destroy their copies at their next
// zone sync. It needs the custodian (503 zone_unavailable otherwise).
func (a *App) DestroyZoneKey(ctx context.Context, name string) error {
	if _, err := a.Core.Do(ctx, http.MethodDelete, "/v1/app/keys/"+url.PathEscape(name)+"?scope="+ScopeZone, nil, nil, nil); err != nil {
		return err
	}
	a.dk.mu.Lock()
	defer a.dk.mu.Unlock()
	if e, ok := a.dk.zone[name]; ok {
		wipe(e.key)
		delete(a.dk.zone, name)
	}
	return nil
}

// DiscoverZone finds live instances of capability on every node of the zone
// (version 0 = any). complete is false when a node could not be asked (a
// node cut off from its Master sees only its own instances). Not cached.
func (a *App) DiscoverZone(ctx context.Context, capability string, version int) (insts []ZoneInstance, complete bool, err error) {
	q := url.Values{"capability": {capability}, "scope": {ScopeZone}}
	if version > 0 {
		q.Set("version", strconv.Itoa(version))
	}
	var out struct {
		Instances []ZoneInstance `json:"instances"`
		Complete  bool           `json:"complete"`
	}
	if _, err := a.Core.Do(ctx, http.MethodGet, "/v1/app/discover?"+q.Encode(), nil, nil, &out); err != nil {
		return nil, false, err
	}
	return out.Instances, out.Complete, nil
}
