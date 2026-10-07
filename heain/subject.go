package heain

// Data-subject rights (Step 4.6d): an app that holds personal data declares
// the shared capability subject.rights (version 1, execution direct) with
// two endpoints, and heain-consent finds every such instance through core's
// discover and calls each one for a person's access, portability or erasure
// request. A person is named by all the identifiers heain-consent knows for
// them; each app matches the ones it uses.
//
//	capabilities:
//	  - {name: subject.rights, version: 1, formal: true, execution: direct, ai: {used: false}}
//	endpoints:
//	  - {method: POST, path: /v1/subject-rights/export, capability: subject.rights, formal: true}
//	  - {method: POST, path: /v1/subject-rights/erase, capability: subject.rights, formal: true}
//
// and in code: srv.HandleSubjectRights(heain.SubjectRights{Export: ..., Erase: ...}).

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// The subject.rights contract.
const (
	SubjectRightsCapability = "subject.rights"
	SubjectRightsExportPath = "/v1/subject-rights/export"
	SubjectRightsErasePath  = "/v1/subject-rights/erase"
)

// Identifier kinds every app should understand where it holds them. Others
// are allowed ("<app>:<kind>", e.g. "heain-access:subject").
const (
	IdentGatewayUser = "gateway_user" // a heain-gateway account id
	IdentEmail       = "email"
	IdentPhone       = "phone"
)

var identKindRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,62}(:[a-z0-9][a-z0-9_.-]{0,62})?$`)

// SubjectIdentifier is one way a person is known.
type SubjectIdentifier struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// NormalizeIdentifier gives the form identifiers are compared in: e-mail
// addresses lower-cased, phone numbers reduced to "+" and digits, other
// values trimmed.
func NormalizeIdentifier(kind, value string) string {
	value = strings.TrimSpace(value)
	switch kind {
	case IdentEmail:
		return strings.ToLower(value)
	case IdentPhone:
		var b strings.Builder
		for i, r := range value {
			if (r >= '0' && r <= '9') || (r == '+' && i == 0) {
				b.WriteRune(r)
			}
		}
		return b.String()
	}
	return value
}

// SubjectRequest is what heain-consent sends to each app.
type SubjectRequest struct {
	Request string `json:"request"` // heain-consent's request id
	// Subject is heain-consent's subject id (opaque). An app that keeps
	// something back (held by retention or a legal hold) after erasing the
	// identifiers that led to it should remember this id with it, so a
	// later pass for the same person (an approved override) still finds it.
	Subject     string              `json:"subject"`
	Identifiers []SubjectIdentifier `json:"identifiers"`
	// DryRun (erase only): answer what would be erased and what is held,
	// and change nothing.
	DryRun bool `json:"dry_run,omitempty"`
	// Override (erase only) is the id of a RETENTION_OVERRIDE action an
	// Approver approved (P5): erase what is held by retention or a legal
	// hold as well.
	Override string `json:"override,omitempty"`
}

// Values returns the request's identifiers of one kind, normalized.
func (r SubjectRequest) Values(kind string) []string {
	var out []string
	for _, id := range r.Identifiers {
		if id.Kind == kind {
			out = append(out, NormalizeIdentifier(kind, id.Value))
		}
	}
	return out
}

// Has reports whether the request names value as an identifier of kind.
func (r SubjectRequest) Has(kind, value string) bool {
	value = NormalizeIdentifier(kind, value)
	for _, v := range r.Values(kind) {
		if v == value && v != "" {
			return true
		}
	}
	return false
}

// SubjectItem is one piece of a person's data in an app.
type SubjectItem struct {
	Kind string `json:"kind"` // what it is in this app: account, contact, file, instance, ...
	ID   string `json:"id"`
	// Data is the item's content (export only).
	Data any `json:"data,omitempty"`
	// Reason says why an item is held: "legal_hold", "retention_min", or
	// another short reason; Until, when known, is when it may go.
	Reason string    `json:"reason,omitempty"`
	Until  time.Time `json:"until,omitempty"`
}

// SubjectExport is an app's answer to an export.
type SubjectExport struct {
	Items []SubjectItem `json:"items"`
}

// SubjectErasure is an app's answer to an erase: what was (or, in a dry
// run, would be) erased, and what is held.
type SubjectErasure struct {
	Erased []SubjectItem `json:"erased"`
	Held   []SubjectItem `json:"held"`
}

// SubjectRights is an app's implementation of the contract.
type SubjectRights struct {
	// Callers are the app ids that may call (default: heain-consent).
	Callers []string
	Export  func(ctx context.Context, r SubjectRequest) (SubjectExport, error)
	Erase   func(ctx context.Context, r SubjectRequest) (SubjectErasure, error)
}

// HandleSubjectRights registers the two endpoints (the manifest must
// declare them, under the capability subject.rights).
func (s *Server) HandleSubjectRights(h SubjectRights) error {
	if h.Export == nil || h.Erase == nil {
		return errors.New("heain-sdk: subject rights need both Export and Erase")
	}
	callers := h.Callers
	if len(callers) == 0 {
		callers = []string{"heain-consent"}
	}
	read := func(w http.ResponseWriter, r *http.Request) (SubjectRequest, bool) {
		var q SubjectRequest
		app, _, _ := strings.Cut(Caller(r.Context()), ".")
		allowed := false
		for _, c := range callers {
			allowed = allowed || c == app
		}
		if !allowed {
			subjectFail(w, http.StatusForbidden, "forbidden", "only "+strings.Join(callers, ", ")+" may make data-subject requests")
			return q, false
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&q); err != nil {
			subjectFail(w, http.StatusBadRequest, "bad_request", "body: {request, subject, identifiers: [{kind, value}], dry_run?, override?}")
			return q, false
		}
		if q.Request == "" || q.Subject == "" || len(q.Identifiers) == 0 || len(q.Identifiers) > 64 {
			subjectFail(w, http.StatusBadRequest, "bad_request", "request, subject and 1 to 64 identifiers are required")
			return q, false
		}
		for _, id := range q.Identifiers {
			if !identKindRe.MatchString(id.Kind) || strings.TrimSpace(id.Value) == "" || len(id.Value) > 512 {
				subjectFail(w, http.StatusBadRequest, "bad_request", "an identifier needs a kind ([a-z0-9_.-], optionally <app>:<kind>) and a value")
				return q, false
			}
		}
		return q, true
	}
	if err := s.HandleFunc("POST "+SubjectRightsExportPath, func(w http.ResponseWriter, r *http.Request) {
		q, ok := read(w, r)
		if !ok {
			return
		}
		if q.DryRun || q.Override != "" {
			subjectFail(w, http.StatusBadRequest, "bad_request", "dry_run and override are for erase")
			return
		}
		out, err := h.Export(r.Context(), q)
		if err != nil {
			subjectFail(w, http.StatusServiceUnavailable, "unavailable", err.Error())
			return
		}
		if out.Items == nil {
			out.Items = []SubjectItem{}
		}
		subjectReply(w, out)
	}); err != nil {
		return err
	}
	return s.HandleFunc("POST "+SubjectRightsErasePath, func(w http.ResponseWriter, r *http.Request) {
		q, ok := read(w, r)
		if !ok {
			return
		}
		out, err := h.Erase(r.Context(), q)
		if err != nil {
			subjectFail(w, http.StatusServiceUnavailable, "unavailable", err.Error())
			return
		}
		// an erase answer never carries the data
		for _, l := range []*[]SubjectItem{&out.Erased, &out.Held} {
			if *l == nil {
				*l = []SubjectItem{}
			}
			for i := range *l {
				(*l)[i].Data = nil
			}
		}
		subjectReply(w, out)
	})
}

func subjectReply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func subjectFail(w http.ResponseWriter, code int, c, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": c, "message": msg}})
}
