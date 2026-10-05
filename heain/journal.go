package heain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// JournalEntry is the answer of POST /v1/app/journal/events.
type JournalEntry struct {
	AppSeq    uint64 `json:"app_seq"`
	Seq       uint64 `json:"seq"`
	HLC       string `json:"hlc"`
	Duplicate bool   `json:"duplicate"`
}

// JournalStatus is GET /v1/app/journal/status.
type JournalStatus struct {
	State           string `json:"state"` // idle | pending | sending | acked
	LastSeq         uint64 `json:"last_seq"`
	AckedThroughSeq uint64 `json:"acked_through_seq"`
	Mode            string `json:"mode"`
}

// Journal writes one of the app's own domain events to the node's offline
// journal (spec 02 §9), e.g. "vote.counted". Formal calls need no journal
// call: their audit events are journaled by core while standalone.
// app_seq comes from a durable counter in Options.StateDir, reserved
// before sending, so a retry reuses its number (core is idempotent by
// app_seq) and a restart never reuses one. data must be JSON-encodable;
// lane, if set, must be declared in the manifest. The trace id is ctx's,
// or a new one.
func (a *App) Journal(ctx context.Context, kind, lane string, data any) (JournalEntry, error) {
	if kind == "" {
		return JournalEntry{}, errors.New("heain-sdk: journal kind is required")
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return JournalEntry{}, err
	}
	trace := TraceID(ctx)
	if trace == "" || (lane != "" && Lane(ctx) != lane) {
		trace = NewID()
	}
	seq, err := a.nextAppSeq()
	if err != nil {
		return JournalEntry{}, err
	}
	body := map[string]any{"app_seq": seq, "trace_id": trace, "kind": kind, "data": json.RawMessage(raw)}
	if lane != "" {
		body["lane"] = lane
	}
	var out JournalEntry
	for i := 0; ; i++ {
		_, err = a.Core.Do(ctx, http.MethodPost, "/v1/app/journal/events", nil, body, &out)
		if err == nil || i == 2 || !retryable(err) {
			break
		}
	}
	out.AppSeq = seq
	return out, err
}

// JournalProgress is the reconcile progress of the node's journal.
func (a *App) JournalProgress(ctx context.Context) (JournalStatus, error) {
	var st JournalStatus
	_, err := a.Core.Do(ctx, http.MethodGet, "/v1/app/journal/status", nil, nil, &st)
	return st, err
}

func (a *App) seqFile() string {
	dir := a.opts.StateDir
	if dir == "" {
		dir = filepath.Dir(a.opts.Core.KeyFile)
	}
	return filepath.Join(dir, fmt.Sprintf(".heain-%s.%s.app_seq", a.Manifest.App.ID, a.Instance))
}

// nextAppSeq reserves the next app_seq durably (written and synced before
// it is used).
func (a *App) nextAppSeq() (uint64, error) {
	a.seqMu.Lock()
	defer a.seqMu.Unlock()
	p := a.seqFile()
	var last uint64
	if raw, err := os.ReadFile(p); err == nil {
		last, err = strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("heain-sdk: %s is corrupt: %w", p, err)
		}
	} else if !os.IsNotExist(err) {
		return 0, err
	}
	next := last + 1
	tmp := p + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, fmt.Errorf("heain-sdk: journal counter: %w", err)
	}
	_, err = f.WriteString(strconv.FormatUint(next, 10))
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, p)
	}
	if err != nil {
		return 0, fmt.Errorf("heain-sdk: journal counter: %w", err)
	}
	return next, nil
}
