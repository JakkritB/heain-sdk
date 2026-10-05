package heain

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// P5 results (spec 02 §6).
const (
	ResultAutoApproved      = "AUTO_APPROVED"
	ResultWaitingApproval   = "WAITING_APPROVAL"
	ResultEmergencyExecuted = "EMERGENCY_EXECUTED"
	ResultApproved          = "APPROVED"
	ResultDenied            = "DENIED"
)

// P5 categories an app may use (SYSTEM_SURVIVAL is core's only).
const (
	CategoryThreshold         = "THRESHOLD_BASED"
	CategoryAllowlist         = "ALLOWLIST_BASED"
	CategoryKnowledgeUpdate   = "KNOWLEDGE_UPDATE"
	CategoryRetentionOverride = "RETENTION_OVERRIDE"
)

// Proposal asks P5 for a decision on an app-defined action.
type Proposal struct {
	Type     string         `json:"type"`
	Category string         `json:"category"`
	Value    float64        `json:"value,omitempty"`
	ZoneID   string         `json:"zone_id,omitempty"`
	Data     map[string]any `json:"data,omitempty"`
}

// PolicyResult is a P5 action and its result.
type PolicyResult struct {
	ActionID string `json:"action_id"`
	Type     string `json:"type,omitempty"`
	Result   string `json:"result"`
}

// Waiting reports whether an Approver still has to decide.
func (r PolicyResult) Waiting() bool { return r.Result == ResultWaitingApproval }

// Allowed reports whether the action may go ahead.
func (r PolicyResult) Allowed() bool {
	return r.Result == ResultAutoApproved || r.Result == ResultApproved || r.Result == ResultEmergencyExecuted
}

// Propose sends p to the P5 gate. It is not retried automatically (each
// proposal is a new action); thresholds and categories are policy set by
// admins, never by the app.
func (a *App) Propose(ctx context.Context, p Proposal) (PolicyResult, error) {
	if p.Type == "" || p.Category == "" {
		return PolicyResult{}, fmt.Errorf("heain-sdk: proposal type and category are required")
	}
	var r PolicyResult
	_, err := a.Core.Do(ctx, http.MethodPost, "/v1/app/policy/propose", nil, p, &r)
	return r, err
}

// PolicyStatus reads the result of one of this instance's proposals.
func (a *App) PolicyStatus(ctx context.Context, actionID string) (PolicyResult, error) {
	var r PolicyResult
	_, err := a.Core.Do(ctx, http.MethodGet, "/v1/app/policy/"+url.PathEscape(actionID), nil, nil, &r)
	return r, err
}

// PolicyPoll is how often WaitPolicy asks.
var PolicyPoll = 2 * time.Second

// WaitPolicy polls until the action is decided or ctx ends.
func (a *App) WaitPolicy(ctx context.Context, actionID string) (PolicyResult, error) {
	for {
		r, err := a.PolicyStatus(ctx, actionID)
		if err == nil && !r.Waiting() {
			return r, nil
		}
		if err != nil && !retryable(err) {
			return r, err
		}
		select {
		case <-ctx.Done():
			return r, ctx.Err()
		case <-time.After(PolicyPoll):
		}
	}
}

// Broadcast proposes a P7 discovery (always through P5, KNOWLEDGE_UPDATE).
// Core sanitizes and validates an approved payload before fan-out.
func (a *App) Broadcast(ctx context.Context, discoveryID, originZone string, payload map[string]any) (PolicyResult, error) {
	var r PolicyResult
	_, err := a.Core.Do(ctx, http.MethodPost, "/v1/app/broadcast", nil,
		map[string]any{"discovery_id": discoveryID, "origin_zone_id": originZone, "payload": payload}, &r)
	return r, err
}
