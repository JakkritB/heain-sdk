package heain

import (
	"context"
	"net/http"
	"time"
)

// Node modes reported by core (spec 02 §9).
const (
	ModeNormal     = "normal"
	ModeStandalone = "standalone"
)

// Mode is GET /v1/app/mode: whether the app's node is cut off from its
// hierarchy (standalone), since when, and the admin's offline policy.
type Mode struct {
	Mode             string     `json:"mode"`
	Since            *time.Time `json:"since,omitempty"`
	Reason           string     `json:"reason,omitempty"`
	LostParent       string     `json:"lost_parent,omitempty"`
	DenyCapabilities []string   `json:"deny_capabilities,omitempty"`
	WarnAfter        string     `json:"warn_after,omitempty"`
	Overdue          bool       `json:"overdue,omitempty"`
}

// Standalone reports whether m is the standalone mode.
func (m Mode) Standalone() bool { return m.Mode == ModeStandalone }

// FetchMode reads the mode from core now (and updates the cached one).
func (a *App) FetchMode(ctx context.Context) (Mode, error) {
	var m Mode
	if _, err := a.Core.Do(ctx, http.MethodGet, "/v1/app/mode", nil, nil, &m); err != nil {
		return a.CurrentMode(), err
	}
	if m.Mode == "" {
		m.Mode = ModeNormal
	}
	a.setMode(m)
	return m, nil
}

// CurrentMode is the mode as last seen (polled every Options.ModePoll).
func (a *App) CurrentMode() Mode {
	a.modeMu.Lock()
	defer a.modeMu.Unlock()
	return a.mode
}

// OnModeChange registers f, called (in its own goroutine) whenever the
// mode changes between normal and standalone, or the offline policy
// changes while standalone.
func (a *App) OnModeChange(f func(old, cur Mode)) {
	a.modeMu.Lock()
	a.modeSubs = append(a.modeSubs, f)
	a.modeMu.Unlock()
}

func (a *App) setMode(m Mode) {
	a.modeMu.Lock()
	old := a.mode
	changed := old.Mode != m.Mode || (m.Standalone() && (!sameStrings(old.DenyCapabilities, m.DenyCapabilities) || old.Overdue != m.Overdue))
	a.mode = m
	subs := append([]func(old, cur Mode){}, a.modeSubs...)
	a.modeMu.Unlock()
	if !changed {
		return
	}
	a.logf("heain-sdk: node mode %s -> %s %s", old.Mode, m.Mode, m.Reason)
	for _, f := range subs {
		go f(old, m)
	}
}

func (a *App) watchMode() {
	defer close(a.modeDone)
	every := a.opts.ModePoll
	if every == 0 {
		every = 5 * time.Second
	}
	if every < 0 {
		<-a.stop
		return
	}
	for {
		select {
		case <-a.stop:
			return
		case <-time.After(every):
		}
		ctx, cancel := context.WithTimeout(context.Background(), every+5*time.Second)
		_, _ = a.FetchMode(ctx)
		cancel()
	}
}

// AllowedNow reports whether capability may be served now: always while
// normal; while standalone only if the manifest's offline.allowed permits
// it (no offline.allowed = all, author decision 2026-10-05, as core) and
// the admin's offline policy does not deny it.
func (a *App) AllowedNow(capability string) bool {
	m := a.CurrentMode()
	if !m.Standalone() {
		return true
	}
	for _, d := range m.DenyCapabilities {
		if d == capability {
			return false
		}
	}
	off := a.Manifest.Offline
	if off == nil || off.Allowed == nil {
		return true
	}
	for _, c := range off.Allowed {
		if c == capability {
			return true
		}
	}
	return false
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
