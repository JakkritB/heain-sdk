// Package jobclient is used by a Layer 3 module (e.g. heain-image,
// heain-videos) to register itself with heain-job's /register endpoint
// and keep that registration alive via periodic re-registration
// ("heartbeat"), and (Stage B, 2026-10-01) to report its own progress on
// a SubUnit it is actively executing. It never imports any heain-job
// package -- the wire contract below is duplicated here deliberately,
// matching how coreclient (in this same repo) duplicates heain-core's
// wire contract for the same reason.
package jobclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// DefaultReregisterInterval is how often KeepRegistered re-sends the
// registration while its context stays alive. It must stay well inside
// heain-job's own registry.DefaultTTL (30s) so a healthy module is never
// mistaken for stale; 15s gives a 2x safety margin against network jitter
// or a single missed tick.
const DefaultReregisterInterval = 15 * time.Second

// DefaultRequestTimeout bounds a single /register, /deregister, or
// /progress call.
const DefaultRequestTimeout = 5 * time.Second

// Endpoint is the registration payload, matching heain-job's
// jobapp.ModuleEndpoint wire shape field-for-field.
//
// ReplicaID (Stage B): distinguishes multiple concurrent instances of
// the same module/strategy from each other. Empty (the default) means
// "this module never runs more than one instance of itself" -- the
// original single-instance case (e.g. heain-image today), and is fully
// backward compatible: every existing caller that never sets this field
// keeps behaving exactly as before.
type Endpoint struct {
	ModuleName   string `json:"module_name"`
	StrategyName string `json:"strategy_name"`
	BaseURL      string `json:"base_url"`
	Token        string `json:"token"`
	ReplicaID    string `json:"replica_id,omitempty"`
}

// ProgressStatus mirrors heain-job's jobapp.ProgressStatus.
type ProgressStatus string

const (
	ProgressRunning ProgressStatus = "RUNNING"
	ProgressDone    ProgressStatus = "DONE"
	ProgressFailed  ProgressStatus = "FAILED"
)

// Client registers a module with one heain-job instance.
type Client struct {
	JobBaseURL string
	httpClient *http.Client
}

// New builds a Client targeting the given heain-job base URL.
func New(jobBaseURL string) *Client {
	return &Client{
		JobBaseURL: jobBaseURL,
		httpClient: &http.Client{Timeout: DefaultRequestTimeout},
	}
}

// Register sends one registration (or re-registration/heartbeat) call.
func (c *Client) Register(ctx context.Context, ep Endpoint) error {
	buf, err := json.Marshal(ep)
	if err != nil {
		return fmt.Errorf("jobclient: encoding registration: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.JobBaseURL+"/register", bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("jobclient: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("jobclient: register request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("jobclient: /register returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// Deregister tells heain-job this module no longer owns strategyName
// under its default (empty) replica, so the very next Lookup against it
// fails immediately (ErrNotRegistered) instead of waiting out the
// up-to-30s staleness TTL. This is the original single-instance
// signature, unchanged for every existing caller -- equivalent to
// DeregisterReplica(ctx, strategyName, "").
func (c *Client) Deregister(ctx context.Context, strategyName string) error {
	return c.DeregisterReplica(ctx, strategyName, "")
}

// DeregisterReplica tells heain-job this specific replica no longer
// owns strategyName (Stage B), without affecting any of that strategy's
// other live replicas. Like Deregister, this is a pure latency
// optimization for graceful shutdown -- never required for correctness,
// since a replica that crashes without calling this simply goes stale
// on the existing TTL path and is handled identically.
func (c *Client) DeregisterReplica(ctx context.Context, strategyName, replicaID string) error {
	buf, err := json.Marshal(map[string]string{"strategy_name": strategyName, "replica_id": replicaID})
	if err != nil {
		return fmt.Errorf("jobclient: encoding deregistration: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.JobBaseURL+"/deregister", bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("jobclient: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("jobclient: deregister request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("jobclient: /deregister returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// ReportProgress (Stage B) tells heain-job how far this replica has
// gotten on one SubUnit it is actively executing, authenticated with
// the same token this replica registered with. See
// design-notes/n-tier-generalization.md, "Progress reporting: replicas
// self-report, not polled from queue depth" in heain-core's repo for the
// full rationale.
func (c *Client) ReportProgress(ctx context.Context, strategyName, replicaID, token, subUnitID string, percentComplete float64, status ProgressStatus) error {
	payload := struct {
		ReplicaID       string         `json:"replica_id"`
		StrategyName    string         `json:"strategy_name"`
		SubUnitID       string         `json:"sub_unit_id"`
		PercentComplete float64        `json:"percent_complete"`
		Status          ProgressStatus `json:"status"`
	}{
		ReplicaID:       replicaID,
		StrategyName:    strategyName,
		SubUnitID:       subUnitID,
		PercentComplete: percentComplete,
		Status:          status,
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("jobclient: encoding progress report: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.JobBaseURL+"/progress", bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("jobclient: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("jobclient: progress request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("jobclient: /progress returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// KeepRegistered registers ep once, then re-registers every interval
// (heain-job treats each re-registration as a heartbeat, refreshing the
// registry's staleness TTL) until ctx is canceled. Run it in its own
// goroutine from a module's main():
//
//	go jobclient.KeepRegistered(ctx, client, ep, jobclient.DefaultReregisterInterval, onErr)
//
// onErr, if non-nil, is called synchronously from that goroutine whenever
// a registration attempt fails. KeepRegistered keeps retrying on the next
// tick regardless -- a transient miss or two is expected to self-heal,
// matching heain-job's own retry/backoff philosophy for transient
// failures.
func KeepRegistered(ctx context.Context, c *Client, ep Endpoint, interval time.Duration, onErr func(error)) {
	if err := c.Register(ctx, ep); err != nil && onErr != nil {
		onErr(err)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.Register(ctx, ep); err != nil && onErr != nil {
				onErr(err)
			}
		}
	}
}
