package heain

// Report sources (Step 4.6h): an app that holds data declares the shared
// capability report.source (version 1, execution direct) and answers
// aggregate queries over its own datasets; heain-report finds every such
// instance through core's discover, merges the answers, hides small groups
// and keeps signed snapshots. The app never hands over its store, only
// aggregates -- and rows only for a run an Approver approved (P5).
//
//	capabilities:
//	  - {name: report.source, version: 1, formal: true, execution: direct, ai: {used: false}}
//	endpoints:
//	  - {method: GET, path: /v1/report-source/datasets, capability: report.source, formal: false}
//	  - {method: POST, path: /v1/report-source/query, capability: report.source, formal: true}
//
// and in code: srv.HandleReportSource(heain.ReportSource{Datasets: ..., Query: ...}).

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// The report.source contract.
const (
	ReportSourceCapability   = "report.source"
	ReportSourceDatasetsPath = "/v1/report-source/datasets"
	ReportSourceQueryPath    = "/v1/report-source/query"
)

// Aggregations a measure may have. They merge across instances: counts and
// sums add up, minimums and maximums take the smaller or larger. An average
// is a sum divided by the group's count, by whoever reads the report.
const (
	AggCount = "count"
	AggSum   = "sum"
	AggMin   = "min"
	AggMax   = "max"
)

var reportNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,62}$`)

// ReportMeasure is one number a dataset can give per group.
type ReportMeasure struct {
	Name string `json:"name"`
	Agg  string `json:"agg"` // count, sum, min or max
	Unit string `json:"unit,omitempty"`
}

// ReportDataset is what an app offers to reports.
type ReportDataset struct {
	Name       string          `json:"name"`
	Title      string          `json:"title,omitempty"`
	Dimensions []string        `json:"dimensions"` // what rows may be grouped and filtered by
	Measures   []ReportMeasure `json:"measures"`
	// Detail: the app can give rows (record by record) for an approved run.
	Detail bool `json:"detail,omitempty"`
}

// ReportQuery is what heain-report asks an instance.
type ReportQuery struct {
	Report  string            `json:"report"` // heain-report's report id
	Run     string            `json:"run"`    // and run id
	Dataset string            `json:"dataset"`
	From    time.Time         `json:"from"` // inclusive
	To      time.Time         `json:"to"`   // exclusive
	GroupBy []string          `json:"group_by,omitempty"`
	Filter  map[string]string `json:"filter,omitempty"` // dimension = value
	// Measures to give (default: all of the dataset's).
	Measures []string `json:"measures,omitempty"`
	// Detail asks for rows as well. DetailAction is the P5 action an
	// Approver approved for this run; heain-report checks it before asking.
	Detail       bool   `json:"detail,omitempty"`
	DetailAction string `json:"detail_action,omitempty"`
	MaxRows      int    `json:"max_rows,omitempty"` // detail rows (default and ceiling 10000)
}

// ReportGroup is one group of an answer: its dimension values, how many
// records it covers, and its measures.
type ReportGroup struct {
	Keys   map[string]string  `json:"keys"`
	Count  int64              `json:"count"`
	Values map[string]float64 `json:"values"`
}

// ReportResult is an instance's answer.
type ReportResult struct {
	Groups []ReportGroup `json:"groups"`
	// Rows (detail only): one map per record, the dataset's dimensions
	// and measures plus whatever the app declares as detail fields.
	Rows      []map[string]any `json:"rows,omitempty"`
	Truncated bool             `json:"truncated,omitempty"`
}

// ReportSource is an app's implementation of the contract.
type ReportSource struct {
	// Callers are the app ids that may query (default: heain-report).
	Callers  []string
	Datasets []ReportDataset
	Query    func(ctx context.Context, q ReportQuery) (ReportResult, error)
}

// MaxReportRows is the most detail rows one answer may hold.
const MaxReportRows = 10000

// ErrReportQuery is returned by ValidateReportQuery.
var ErrReportQuery = errors.New("heain-sdk: bad report query")

// Dataset finds a dataset by name.
func (s ReportSource) Dataset(name string) (ReportDataset, bool) {
	for _, d := range s.Datasets {
		if d.Name == name {
			return d, true
		}
	}
	return ReportDataset{}, false
}

// ValidateReportDatasets checks a source's declarations.
func ValidateReportDatasets(ds []ReportDataset) error {
	seen := map[string]bool{}
	for _, d := range ds {
		if !reportNameRe.MatchString(d.Name) || seen[d.Name] {
			return errors.New("heain-sdk: report dataset " + d.Name + ": a unique name [a-z0-9_.-] is needed")
		}
		seen[d.Name] = true
		names := map[string]bool{}
		for _, x := range d.Dimensions {
			if !reportNameRe.MatchString(x) || names[x] {
				return errors.New("heain-sdk: report dataset " + d.Name + ": bad or repeated dimension " + x)
			}
			names[x] = true
		}
		if len(d.Measures) == 0 {
			return errors.New("heain-sdk: report dataset " + d.Name + ": at least one measure is needed")
		}
		for _, m := range d.Measures {
			if !reportNameRe.MatchString(m.Name) || names[m.Name] {
				return errors.New("heain-sdk: report dataset " + d.Name + ": bad or repeated measure " + m.Name)
			}
			names[m.Name] = true
			switch m.Agg {
			case AggCount, AggSum, AggMin, AggMax:
			default:
				return errors.New("heain-sdk: report dataset " + d.Name + ": measure " + m.Name + ": agg is count, sum, min or max")
			}
		}
	}
	return nil
}

// ValidateReportQuery checks a query against a dataset and fills in the
// default measures and row limit.
func ValidateReportQuery(d ReportDataset, q *ReportQuery) error {
	bad := func(msg string) error { return errors.New(ErrReportQuery.Error() + ": " + msg) }
	if q.From.IsZero() || q.To.IsZero() || !q.From.Before(q.To) {
		return bad("from must be before to")
	}
	dims := map[string]bool{}
	for _, x := range d.Dimensions {
		dims[x] = true
	}
	if len(q.GroupBy) > 8 {
		return bad("at most 8 group_by dimensions")
	}
	for _, g := range q.GroupBy {
		if !dims[g] {
			return bad("unknown dimension " + g)
		}
	}
	for k := range q.Filter {
		if !dims[k] {
			return bad("unknown filter dimension " + k)
		}
	}
	ms := map[string]bool{}
	for _, m := range d.Measures {
		ms[m.Name] = true
	}
	if len(q.Measures) == 0 {
		for _, m := range d.Measures {
			q.Measures = append(q.Measures, m.Name)
		}
	}
	for _, m := range q.Measures {
		if !ms[m] {
			return bad("unknown measure " + m)
		}
	}
	if q.Detail {
		if !d.Detail {
			return bad("dataset " + d.Name + " gives no detail")
		}
		if q.DetailAction == "" {
			return bad("detail needs the approved P5 action (detail_action)")
		}
	}
	if q.MaxRows <= 0 || q.MaxRows > MaxReportRows {
		q.MaxRows = MaxReportRows
	}
	return nil
}

// HandleReportSource registers the two endpoints (the manifest must
// declare them, under the capability report.source).
func (s *Server) HandleReportSource(h ReportSource) error {
	if h.Query == nil {
		return errors.New("heain-sdk: a report source needs Query")
	}
	if err := ValidateReportDatasets(h.Datasets); err != nil {
		return err
	}
	callers := h.Callers
	if len(callers) == 0 {
		callers = []string{"heain-report"}
	}
	allowed := func(w http.ResponseWriter, r *http.Request) bool {
		app, _, _ := strings.Cut(Caller(r.Context()), ".")
		for _, c := range callers {
			if c == app {
				return true
			}
		}
		subjectFail(w, http.StatusForbidden, "forbidden", "only "+strings.Join(callers, ", ")+" may query report sources")
		return false
	}
	if err := s.HandleFunc("GET "+ReportSourceDatasetsPath, func(w http.ResponseWriter, r *http.Request) {
		if !allowed(w, r) {
			return
		}
		ds := h.Datasets
		if ds == nil {
			ds = []ReportDataset{}
		}
		subjectReply(w, map[string]any{"datasets": ds})
	}); err != nil {
		return err
	}
	return s.HandleFunc("POST "+ReportSourceQueryPath, func(w http.ResponseWriter, r *http.Request) {
		if !allowed(w, r) {
			return
		}
		var q ReportQuery
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&q); err != nil {
			subjectFail(w, http.StatusBadRequest, "bad_request", "body: {report, run, dataset, from, to, group_by, filter, measures, detail, detail_action, max_rows}")
			return
		}
		d, ok := h.Dataset(q.Dataset)
		if !ok {
			subjectFail(w, http.StatusNotFound, "not_found", "no dataset "+q.Dataset)
			return
		}
		if err := ValidateReportQuery(d, &q); err != nil {
			subjectFail(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		out, err := h.Query(r.Context(), q)
		if err != nil {
			subjectFail(w, http.StatusServiceUnavailable, "unavailable", err.Error())
			return
		}
		if out.Groups == nil {
			out.Groups = []ReportGroup{}
		}
		if !q.Detail {
			out.Rows = nil // rows only for an approved detail run
		} else if len(out.Rows) > q.MaxRows {
			out.Rows, out.Truncated = out.Rows[:q.MaxRows], true
		}
		subjectReply(w, out)
	})
}

// ReportAggregator builds an answer from an app's own records, for the
// apps that keep them in a plain store: Add each record that falls in the
// query's window, then Result.
type ReportAggregator struct {
	q      ReportQuery
	aggs   map[string]string
	groups map[string]*ReportGroup
	order  []string
	rows   []map[string]any
	trunc  bool
}

// NewReportAggregator starts an answer to q over dataset d (q already
// validated by the server).
func NewReportAggregator(d ReportDataset, q ReportQuery) *ReportAggregator {
	a := &ReportAggregator{q: q, aggs: map[string]string{}, groups: map[string]*ReportGroup{}}
	for _, m := range d.Measures {
		a.aggs[m.Name] = m.Agg
	}
	return a
}

// Add counts one record: when it happened, its dimension values, its
// measure values (a count measure ignores its value) and, for a detail
// run, its row. Records outside the window or the filter are skipped.
func (a *ReportAggregator) Add(t time.Time, dims map[string]string, values map[string]float64, row map[string]any) {
	if t.Before(a.q.From) || !t.Before(a.q.To) {
		return
	}
	for k, v := range a.q.Filter {
		if dims[k] != v {
			return
		}
	}
	keys := map[string]string{}
	var id strings.Builder
	for _, g := range a.q.GroupBy {
		keys[g] = dims[g]
		id.WriteString(dims[g])
		id.WriteByte(0)
	}
	g := a.groups[id.String()]
	if g == nil {
		g = &ReportGroup{Keys: keys, Values: map[string]float64{}}
		a.groups[id.String()] = g
		a.order = append(a.order, id.String())
	}
	g.Count++
	for _, m := range a.q.Measures {
		v, have := values[m]
		switch a.aggs[m] {
		case AggCount:
			g.Values[m]++
		case AggSum:
			g.Values[m] += v
		case AggMin:
			if old, ok := g.Values[m]; have && (!ok || v < old) {
				g.Values[m] = v
			}
		case AggMax:
			if old, ok := g.Values[m]; have && (!ok || v > old) {
				g.Values[m] = v
			}
		}
	}
	if a.q.Detail && row != nil {
		if len(a.rows) < a.q.MaxRows {
			a.rows = append(a.rows, row)
		} else {
			a.trunc = true
		}
	}
}

// Result is the answer, groups in the order they were first seen.
func (a *ReportAggregator) Result() ReportResult {
	out := ReportResult{Groups: []ReportGroup{}, Rows: a.rows, Truncated: a.trunc}
	for _, id := range a.order {
		out.Groups = append(out.Groups, *a.groups[id])
	}
	return out
}

// MergeReportGroups adds b's groups into a (answers from several instances
// of the same dataset), by the dimension values asked for.
func MergeReportGroups(a, b []ReportGroup, groupBy []string, aggs map[string]string) []ReportGroup {
	key := func(g ReportGroup) string {
		var s strings.Builder
		for _, d := range groupBy {
			s.WriteString(g.Keys[d])
			s.WriteByte(0)
		}
		return s.String()
	}
	at := map[string]int{}
	out := make([]ReportGroup, 0, len(a)+len(b))
	for _, g := range a {
		at[key(g)] = len(out)
		out = append(out, ReportGroup{Keys: g.Keys, Count: g.Count, Values: copyValues(g.Values)})
	}
	for _, g := range b {
		i, ok := at[key(g)]
		if !ok {
			at[key(g)] = len(out)
			out = append(out, ReportGroup{Keys: g.Keys, Count: g.Count, Values: copyValues(g.Values)})
			continue
		}
		o := &out[i]
		o.Count += g.Count
		for m, v := range g.Values {
			old, have := o.Values[m]
			switch aggs[m] {
			case AggMin:
				if !have || v < old {
					o.Values[m] = v
				}
			case AggMax:
				if !have || v > old {
					o.Values[m] = v
				}
			default:
				o.Values[m] = old + v
			}
		}
	}
	return out
}

func copyValues(m map[string]float64) map[string]float64 {
	c := make(map[string]float64, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}
