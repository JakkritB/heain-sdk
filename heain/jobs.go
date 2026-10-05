package heain

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/heainframework/heain-sdk/core"
)

// Classification is the job's requested handling (spec 02 §5); empty
// fields take the deployment's policy defaults, and values outside the
// policy are refused by core (classification_not_allowed).
type Classification struct {
	Delivery                     string `json:"delivery,omitempty"`          // STAGED | IMMEDIATE
	Disposal                     string `json:"disposal,omitempty"`          // RETRIEVAL_CONFIRMED | TIMEOUT_BASED | RIGHT_TO_ERASURE_REQUEST
	OutputEncryption             string `json:"output_encryption,omitempty"` // e.g. STAY_ENCRYPTED
	LegalHold                    bool   `json:"legal_hold,omitempty"`
	MandatoryMinRetentionSeconds int64  `json:"mandatory_min_retention_seconds,omitempty"`
}

// Requirements is what a Worker must have to run the job.
type Requirements struct {
	MinMemoryMB    uint64 `json:"min_memory_mb,omitempty"`
	GPU            string `json:"gpu,omitempty"` // none | optional | required
	MinGPUMemoryMB uint64 `json:"min_gpu_memory_mb,omitempty"`
}

// JobRequest submits work for an execution: job capability (P1).
type JobRequest struct {
	Capability     string
	Version        int
	OriginZone     string
	Payload        []byte
	Classification Classification
	Requirements   Requirements
	// IdempotencyKey makes a resubmission return the same ticket. Empty:
	// one is generated (and reused by the SDK's own retries).
	IdempotencyKey string
}

// Ticket identifies a submitted job.
type Ticket struct {
	TicketID string `json:"ticket_id"`
	TraceID  string `json:"trace_id"`
}

// JobStatus is GET /v1/app/jobs/{ticket}.
type JobStatus struct {
	TicketID    string     `json:"ticket_id"`
	TraceID     string     `json:"trace_id"`
	Capability  string     `json:"capability"`
	State       string     `json:"state"`
	Attempts    int        `json:"attempts"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Output      []byte     `json:"output_b64,omitempty"` // when completed
}

// Job states as core reports them.
const (
	JobQueued           = "queued"
	JobLeased           = "leased"
	JobCompleted        = "completed"
	JobDelivered        = "delivered"
	JobRetriesExhausted = "retries_exhausted"
	JobDisposed         = "disposed"
)

// Done reports whether the job will not change any more by itself.
func (s JobStatus) Done() bool {
	switch s.State {
	case JobCompleted, JobDelivered, JobRetriesExhausted, JobDisposed:
		return true
	}
	return false
}

// Submit queues a job. The capability must be a dependency declared in
// uses[] (checked before any network call). A transient failure is retried
// with the same idempotency key, so the job is queued at most once.
func (a *App) Submit(ctx context.Context, r JobRequest) (Ticket, error) {
	if !a.usesCapability(r.Capability) {
		return Ticket{}, fmt.Errorf("heain-sdk: job capability %s %w", r.Capability, ErrNotDeclared)
	}
	key := r.IdempotencyKey
	if key == "" {
		key = NewID()
	}
	body := map[string]any{"capability": r.Capability, "capability_version": r.Version, "origin_zone": r.OriginZone,
		"payload_b64": r.Payload, "classification": r.Classification, "requirements": r.Requirements}
	var t Ticket
	var err error
	for i := 0; ; i++ {
		_, err = a.Core.Do(ctx, http.MethodPost, "/v1/app/jobs", http.Header{"Idempotency-Key": {key}}, body, &t)
		if err == nil || i == 2 || !retryable(err) {
			return t, err
		}
		select {
		case <-ctx.Done():
			return t, ctx.Err()
		case <-time.After(time.Duration(i+1) * 500 * time.Millisecond):
		}
	}
}

// Job reads a job's status and, once completed, its output. Only the
// submitting instance may read it.
func (a *App) Job(ctx context.Context, ticket string) (JobStatus, error) {
	var s JobStatus
	_, err := a.Core.Do(ctx, http.MethodGet, "/v1/app/jobs/"+url.PathEscape(ticket), nil, nil, &s)
	return s, err
}

// JobPoll is how often WaitJob asks.
var JobPoll = time.Second

// WaitJob polls until the job is done (see JobStatus.Done) or ctx ends.
func (a *App) WaitJob(ctx context.Context, ticket string) (JobStatus, error) {
	for {
		s, err := a.Job(ctx, ticket)
		if err == nil && s.Done() {
			return s, nil
		}
		if err != nil && !retryable(err) {
			return s, err
		}
		select {
		case <-ctx.Done():
			return s, ctx.Err()
		case <-time.After(JobPoll):
		}
	}
}

// ConfirmRetrieval tells P4 the output was received (disposal trigger).
func (a *App) ConfirmRetrieval(ctx context.Context, ticket string) error {
	_, err := a.Core.Do(ctx, http.MethodPost, "/v1/app/jobs/"+url.PathEscape(ticket)+"/confirm-retrieval", nil, map[string]any{}, nil)
	return err
}

// RequestErasure asks P4 to erase the output (right to erasure). A legal
// hold or mandatory retention answers policy_waiting_approval (409).
func (a *App) RequestErasure(ctx context.Context, ticket string) error {
	_, err := a.Core.Do(ctx, http.MethodPost, "/v1/app/jobs/"+url.PathEscape(ticket)+"/request-erasure", nil, map[string]any{}, nil)
	return err
}

func (a *App) usesCapability(capability string) bool {
	for _, u := range a.Manifest.Uses {
		for _, c := range u.Capabilities {
			if c == capability {
				return true
			}
		}
	}
	return false
}

// retryable: transport errors and core errors marked retryable (or 5xx);
// never a cancelled or expired ctx.
func retryable(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var ce *core.Error
	if errors.As(err, &ce) {
		return ce.Retryable || ce.Status >= 500
	}
	return true
}
