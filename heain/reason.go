package heain

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// Decision is what an app tells the SDK about one AI decision; the SDK
// turns it into an AI reasoning record (spec 04) and sends it to core.
type Decision struct {
	Capability string // must declare ai.used: true
	// Input is hashed (SHA-256) and its size kept; the raw input never
	// leaves the SDK (spec 04 rule 1).
	Input          []byte
	InputDataClass string
	InputRef       string
	Decision       string         // the action taken or recommended
	Value          map[string]any // structured result
	Threshold      *Threshold
	Confidence     *float64 // 0..1
	Summary        string
	Factors        []Factor
	// Role: "advisory" (default) or "decision"; a decision needs >= 1
	// factor (decided 2026-10-05).
	Role string
	// ModelSHA256 and Runtime describe the weights actually loaded.
	ModelSHA256, Runtime string
	HumanReview          *HumanReview
	// Corrects names an earlier record this one corrects (records are
	// never edited, rule 2).
	Corrects string
}

type Threshold struct {
	Name   string  `json:"name"`
	Value  float64 `json:"value"`
	Source string  `json:"source"` // policy | app
}

type Factor struct {
	Name  string `json:"name"`
	Value any    `json:"value"`
}

type HumanReview struct {
	Required bool   `json:"required"`
	By       string `json:"by,omitempty"`
	At       string `json:"at,omitempty"`
}

// Record is the wire form of a reasoning record (spec 04 §1).
type Record struct {
	RecordVersion int            `json:"record_version"`
	RecordID      string         `json:"record_id"`
	TraceID       string         `json:"trace_id"`
	Lane          string         `json:"lane,omitempty"`
	App           map[string]any `json:"app"`
	Capability    map[string]any `json:"capability"`
	Model         map[string]any `json:"model"`
	Input         map[string]any `json:"input"`
	Output        map[string]any `json:"output"`
	Confidence    *float64       `json:"confidence,omitempty"`
	Reasoning     map[string]any `json:"reasoning"`
	Role          string         `json:"role"`
	HumanReview   *HumanReview   `json:"human_review,omitempty"`
	Corrects      string         `json:"corrects,omitempty"`
	At            string         `json:"at"`
	HLC           *string        `json:"hlc"`
	Signature     string         `json:"signature,omitempty"`
}

// ErrNotAI is returned for a capability that declares ai.used: false.
var ErrNotAI = errors.New("capability does not declare ai.used: true")

// Reason builds, signs and sends a reasoning record for d in the formal
// process of ctx (its trace and lane), and returns the record id. Inside a
// served request the id is attached to that call's audit event.
func (a *App) Reason(ctx context.Context, d Decision) (string, error) {
	rec, err := a.buildRecord(ctx, d)
	if err != nil {
		return "", err
	}
	var out struct {
		RecordID string `json:"record_id"`
	}
	if _, err := a.Core.Do(ctx, http.MethodPost, "/v1/app/ai/reasoning", nil, rec, &out); err != nil {
		return "", err
	}
	if sink, ok := ctx.Value(keyRecords).(*recordSink); ok {
		sink.add(rec.RecordID)
	}
	return rec.RecordID, nil
}

func (a *App) buildRecord(ctx context.Context, d Decision) (Record, error) {
	c, ok := a.Manifest.Capability(d.Capability)
	if !ok {
		return Record{}, fmt.Errorf("heain-sdk: %s is not in the manifest", d.Capability)
	}
	if c.AI.Used == nil || !*c.AI.Used || c.AI.Model == nil {
		return Record{}, fmt.Errorf("heain-sdk: %s: %w", d.Capability, ErrNotAI)
	}
	role := d.Role
	if role == "" {
		role = "advisory"
	}
	if role != "advisory" && role != "decision" {
		return Record{}, fmt.Errorf("heain-sdk: role must be advisory or decision")
	}
	if role == "decision" && len(d.Factors) == 0 {
		return Record{}, fmt.Errorf("heain-sdk: a record with role decision needs at least one factor")
	}
	if d.Confidence != nil && (*d.Confidence < 0 || *d.Confidence > 1) {
		return Record{}, fmt.Errorf("heain-sdk: confidence must be within 0..1")
	}
	trace, lane := TraceID(ctx), Lane(ctx)
	if trace == "" {
		trace = NewID()
	}
	if c.Lane != "" {
		if lane != "" && lane != c.Lane {
			return Record{}, fmt.Errorf("heain-sdk: lane_violation: %s belongs to lane %q, the process is in %q", c.Name, c.Lane, lane)
		}
		lane = c.Lane
	}
	sum := sha256.Sum256(d.Input)
	in := map[string]any{"sha256": hex.EncodeToString(sum[:]), "size_bytes": len(d.Input)}
	if d.InputDataClass != "" {
		in["data_class"] = d.InputDataClass
	}
	if d.InputRef != "" {
		in["ref"] = d.InputRef
	}
	model := map[string]any{"name": c.AI.Model.Name, "version": c.AI.Model.Version}
	if d.ModelSHA256 != "" {
		model["artifact_sha256"] = d.ModelSHA256
	}
	if d.Runtime != "" {
		model["runtime"] = d.Runtime
	}
	output := map[string]any{"decision": d.Decision}
	if d.Value != nil {
		output["value"] = d.Value
	}
	if d.Threshold != nil {
		output["threshold"] = d.Threshold
	}
	factors := d.Factors
	if factors == nil {
		factors = []Factor{}
	}
	rec := Record{RecordVersion: 1, RecordID: NewID(), TraceID: trace, Lane: lane,
		App:        map[string]any{"id": a.Manifest.App.ID, "version": a.Manifest.App.Version, "instance_id": a.Instance},
		Capability: map[string]any{"name": c.Name, "version": c.Version}, Model: model, Input: in, Output: output,
		Confidence: d.Confidence, Reasoning: map[string]any{"summary": d.Summary, "factors": factors}, Role: role,
		HumanReview: d.HumanReview, Corrects: d.Corrects, At: time.Now().UTC().Format(time.RFC3339)}
	sig, err := a.sign(rec)
	if err != nil {
		return Record{}, err
	}
	rec.Signature = sig
	return rec, nil
}

// sign signs the JCS form of rec (without its signature) with the app key.
func (a *App) sign(rec Record) (string, error) {
	rec.Signature = ""
	canon, err := Canonical(rec)
	if err != nil {
		return "", err
	}
	signer, ok := a.key.(crypto.Signer)
	if !ok {
		return "", fmt.Errorf("heain-sdk: the app key cannot sign")
	}
	h := sha256.Sum256(canon)
	sig, err := signer.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// VerifyRecord checks a record's signature against the certificate that
// signed it (for heain-audit and conformance).
func VerifyRecord(rec Record, cert *tls.Certificate) error {
	return verifySig(rec, cert)
}
