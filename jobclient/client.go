// Package jobclient is used by a Layer 3 module (e.g. heain-image) to
// register itself with heain-job's /register endpoint and keep that
// registration alive via periodic re-registration ("heartbeat"). It
// never imports any heain-job package -- the wire contract below is
// duplicated here deliberately, matching how coreclient (in this same
// repo) duplicates heain-core's wire contract for the same reason.
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

// DefaultRequestTimeout bounds a single /register call.
const DefaultRequestTimeout = 5 * time.Second

// Endpoint is the registration payload, matching heain-job's
// jobapp.ModuleEndpoint wire shape field-for-field.
type Endpoint struct {
	ModuleName   string `json:"module_name"`
	StrategyName string `json:"strategy_name"`
	BaseURL      string `json:"base_url"`
	Token        string `json:"token"`
}

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
