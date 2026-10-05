package heain

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/heainframework/heain-sdk/core"
	"github.com/heainframework/heain-sdk/manifest"
)

// Job is one claimed job, held under a lease until it is completed or
// failed. Its payload exists only in this process's memory (and the
// node's core); the SDK zeroes it after the handler returns.
type Job struct {
	TicketID       string
	LeaseID        string
	LeaseExpiresAt time.Time
	Capability     string
	TraceID        string
	Payload        []byte
}

// JobHandler runs one job and returns its output. Return Permanent(err)
// for a failure that a retry cannot fix; any other error is retried by
// core (up to p3.max_retry, then the job goes to an Approver). ctx carries
// the job's trace and lane (for App.Reason) and ends when the lease does;
// while the handler runs the Worker extends the lease (see Worker.FixedLease),
// so ctx ends only if an extension is refused or core cannot be reached
// before the lease runs out. ctx.Deadline() is not updated by extensions.
type JobHandler func(ctx context.Context, job *Job) ([]byte, error)

type permanentError struct{ err error }

func (p permanentError) Error() string { return p.err.Error() }
func (p permanentError) Unwrap() error { return p.err }

// Permanent marks a job failure as not retryable.
func Permanent(err error) error { return permanentError{err} }

// Worker claims and runs jobs for this app's execution: job capabilities
// (pull model, spec 02 §5) from the core on its own node.
type Worker struct {
	app      *App
	handlers map[string]JobHandler
	caps     map[string]manifest.Capability
	// Concurrency is how many jobs run at once (default 1).
	Concurrency int
	// Wait is the claim long-poll length (default 25 s, core caps it at 30 s).
	Wait time.Duration
	// FixedLease turns off lease extension: by default the Worker asks core
	// (POST /v1/app/jobs/{t}/extend) to extend the lease about every third
	// of its length while the handler runs, so long jobs keep their lease.
	FixedLease bool
}

// NewWorker creates a worker for a.
func (a *App) NewWorker() *Worker {
	return &Worker{app: a, handlers: map[string]JobHandler{}, caps: map[string]manifest.Capability{}}
}

// Handle sets the handler of capability, which must be declared in the
// manifest with execution: job.
func (w *Worker) Handle(capability string, h JobHandler) error {
	c, ok := w.app.Manifest.Capability(capability)
	if !ok || c.Execution != "job" {
		return fmt.Errorf("heain-sdk: %s is not an execution: job capability of this app's manifest", capability)
	}
	w.handlers[capability] = h
	w.caps[capability] = c
	return nil
}

// Run claims and runs jobs until ctx ends. While the node is standalone it
// claims only capabilities allowed offline (App.AllowedNow).
func (w *Worker) Run(ctx context.Context) error {
	if len(w.handlers) == 0 {
		return errors.New("heain-sdk: worker has no handlers")
	}
	n := w.Concurrency
	if n <= 0 {
		n = 1
	}
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.loop(ctx)
		}()
	}
	wg.Wait()
	return ctx.Err()
}

func (w *Worker) loop(ctx context.Context) {
	wait := w.Wait
	if wait <= 0 || wait > 30*time.Second {
		wait = 25 * time.Second
	}
	backoff := time.Second
	for ctx.Err() == nil {
		var caps []string
		for c := range w.handlers {
			if w.app.AllowedNow(c) {
				caps = append(caps, c)
			}
		}
		if len(caps) == 0 {
			sleepCtx(ctx, 2*time.Second)
			continue
		}
		var out struct {
			TicketID       string    `json:"ticket_id"`
			LeaseID        string    `json:"lease_id"`
			LeaseExpiresAt time.Time `json:"lease_expires_at"`
			Capability     string    `json:"capability"`
			TraceID        string    `json:"trace_id"`
			Payload        []byte    `json:"payload_b64"`
		}
		cctx, cancel := context.WithTimeout(ctx, wait+10*time.Second)
		st, err := w.app.Core.LongPoll(cctx, http.MethodPost, "/v1/app/jobs/claim", map[string]any{"capabilities": caps, "wait_s": int(wait / time.Second)}, &out)
		cancel()
		if err != nil {
			if ctx.Err() == nil {
				w.app.logf("heain-sdk: claim failed: %v", err)
				sleepCtx(ctx, backoff)
				if backoff < 30*time.Second {
					backoff *= 2
				}
			}
			continue
		}
		backoff = time.Second
		if st == http.StatusNoContent || out.TicketID == "" {
			continue
		}
		w.run(ctx, &Job{TicketID: out.TicketID, LeaseID: out.LeaseID, LeaseExpiresAt: out.LeaseExpiresAt,
			Capability: out.Capability, TraceID: out.TraceID, Payload: out.Payload})
	}
}

// run executes one job: handler, reasoning-record rule, formal audit (one
// event per attempt; if it cannot be written the attempt fails and is
// retried), then complete or fail.
func (w *Worker) run(ctx context.Context, j *Job) {
	defer wipe(j.Payload)
	c, h := w.caps[j.Capability], w.handlers[j.Capability]
	trace := j.TraceID
	if trace == "" {
		trace = NewID()
	}
	sink := &recordSink{}
	jctx := WithTrace(ctx, trace, c.Lane)
	jctx = context.WithValue(jctx, keyRecords, sink)
	if !j.LeaseExpiresAt.IsZero() {
		var cancel context.CancelFunc
		jctx, cancel = context.WithCancel(jctx)
		stop := w.keepLease(cancel, j)
		defer stop()
		defer cancel()
	}
	var output []byte
	var herr error
	if h == nil {
		herr = Permanent(fmt.Errorf("no handler for %s", j.Capability))
	} else {
		output, herr = safeRun(jctx, h, j)
	}
	defer wipe(output)
	ids := sink.list()
	recordRequired := c.AI.Used != nil && *c.AI.Used && c.AI.ReasoningRecord != "optional"
	outcome, reason, retry := "ok", "", true
	switch {
	case herr != nil:
		outcome, reason = "error:job_failed", herr.Error()
		var p permanentError
		retry = !errors.As(herr, &p)
	case recordRequired && len(ids) == 0:
		outcome, reason, retry = "error:reasoning_record_missing", j.Capability+" uses AI and must send a reasoning record (App.Reason) for every decision", false
		w.app.logf("heain-sdk: job %s finished without the reasoning record %s requires -- failed", j.TicketID, j.Capability)
	}
	// Final calls to core use a fresh context: the lease ctx may have ended.
	fctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if c.Formal != nil && *c.Formal {
		detail := map[string]any{"ticket_id": j.TicketID}
		if len(ids) > 0 {
			detail["reasoning_record_ids"] = ids
		}
		if reason != "" {
			detail["reason"] = reason
		}
		if err := w.app.auditEvent(fctx, trace, c.Lane, c.Name, w.app.Manifest.App.ID+"."+w.app.Instance, outcome, detail); err != nil {
			w.app.logf("heain-sdk: audit of job %s failed, result withheld: %v", j.TicketID, err)
			outcome, reason, retry = "error:audit_unavailable", "the formal process could not be logged", true
		}
	}
	path := "/v1/app/jobs/" + url.PathEscape(j.TicketID)
	var err error
	if outcome == "ok" {
		_, err = w.app.Core.Do(fctx, http.MethodPost, path+"/complete", nil, map[string]any{"lease_id": j.LeaseID,
			"output_b64": base64.StdEncoding.EncodeToString(output), "reasoning_record_ids": ids}, nil)
	} else {
		_, err = w.app.Core.Do(fctx, http.MethodPost, path+"/fail", nil, map[string]any{"lease_id": j.LeaseID, "retryable": retry, "reason": reason}, nil)
	}
	if err != nil {
		w.app.logf("heain-sdk: job %s: reporting %s to core failed: %v", j.TicketID, outcome, err)
	}
}

// keepLease ends the job ctx (cancel) when the lease runs out and, unless
// FixedLease, extends the lease every third of its length. stop ends it.
func (w *Worker) keepLease(cancel context.CancelFunc, j *Job) (stop func()) {
	expires := j.LeaseExpiresAt
	length := time.Until(expires)
	if length < time.Second {
		length = time.Second
	}
	every := length / 3
	secs := int((length + time.Second - 1) / time.Second)
	path := "/v1/app/jobs/" + url.PathEscape(j.TicketID) + "/extend"
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		extend := !w.FixedLease
		for {
			wait := time.Until(expires)
			if wait <= 0 {
				w.app.logf("heain-sdk: job %s: lease ran out", j.TicketID)
				cancel()
				return
			}
			if extend && every < wait {
				wait = every
			}
			select {
			case <-done:
				return
			case <-time.After(wait):
			}
			if !extend || time.Now().After(expires) {
				continue
			}
			ctx, c := context.WithTimeout(context.Background(), time.Until(expires))
			var out struct {
				LeaseExpiresAt time.Time `json:"lease_expires_at"`
			}
			_, err := w.app.Core.Do(ctx, http.MethodPost, path, nil, map[string]any{"lease_id": j.LeaseID, "seconds": secs}, &out)
			c()
			switch {
			case err == nil && !out.LeaseExpiresAt.IsZero():
				expires = out.LeaseExpiresAt
			case refused(err):
				// refused (lease_expired, not local, ...): stop asking; ctx
				// ends when the current lease does.
				w.app.logf("heain-sdk: job %s: lease extension refused: %v", j.TicketID, err)
				extend = false
			case err != nil:
				w.app.logf("heain-sdk: job %s: lease extension failed (will retry): %v", j.TicketID, err)
			}
		}
	}()
	return func() { close(done); <-finished }
}

// refused reports a definite answer from core (4xx, not retryable).
func refused(err error) bool {
	var ce *core.Error
	return errors.As(err, &ce) && ce.Status >= 400 && ce.Status < 500 && !ce.Retryable
}

func safeRun(ctx context.Context, h JobHandler, j *Job) (out []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("handler panicked: %v", r)
		}
	}()
	return h(ctx, j)
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func sleepCtx(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}
