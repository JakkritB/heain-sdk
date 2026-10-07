package heain

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/heainframework/heain-sdk/core"
	"github.com/heainframework/heain-sdk/internal/testpki"
)

const reportManifest = `manifest_version: 1
app: {id: shop-app, version: 1.0.0, group: domain, api: v1, sdk: {name: heain-sdk-go, version: ">=1.0.0"}}
capabilities:
  - {name: report.source, version: 1, formal: true, execution: direct, ai: {used: false}}
endpoints:
  - {method: GET, path: /v1/report-source/datasets, capability: report.source, formal: false}
  - {method: POST, path: /v1/report-source/query, capability: report.source, formal: true}
`

var salesDS = ReportDataset{Name: "sales", Dimensions: []string{"branch", "product"}, Detail: true,
	Measures: []ReportMeasure{{Name: "orders", Agg: AggCount}, {Name: "amount", Agg: AggSum, Unit: "THB"}, {Name: "largest", Agg: AggMax}}}

func TestReportAggregator(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	q := ReportQuery{Dataset: "sales", From: t0, To: t0.Add(24 * time.Hour), GroupBy: []string{"branch"}, Filter: map[string]string{"product": "tea"}}
	if err := ValidateReportQuery(salesDS, &q); err != nil || len(q.Measures) != 3 || q.MaxRows != MaxReportRows {
		t.Fatalf("validate: %v %+v", err, q)
	}
	a := NewReportAggregator(salesDS, q)
	add := func(h int, branch, product string, amt float64) {
		a.Add(t0.Add(time.Duration(h)*time.Hour), map[string]string{"branch": branch, "product": product}, map[string]float64{"amount": amt, "largest": amt}, map[string]any{"amount": amt})
	}
	add(1, "bkk", "tea", 10)
	add(2, "bkk", "tea", 30)
	add(3, "cnx", "tea", 5)
	add(4, "bkk", "coffee", 99) // filtered out
	add(25, "bkk", "tea", 70)   // outside the window
	r := a.Result()
	if len(r.Groups) != 2 || r.Groups[0].Count != 2 || r.Groups[0].Values["amount"] != 40 || r.Groups[0].Values["orders"] != 2 ||
		r.Groups[0].Values["largest"] != 30 || r.Groups[1].Keys["branch"] != "cnx" || r.Rows != nil {
		t.Fatalf("result: %+v", r)
	}
	m := MergeReportGroups(r.Groups, []ReportGroup{{Keys: map[string]string{"branch": "bkk"}, Count: 1, Values: map[string]float64{"amount": 5, "orders": 1, "largest": 50}},
		{Keys: map[string]string{"branch": "hkt"}, Count: 3, Values: map[string]float64{"amount": 1}}}, q.GroupBy, map[string]string{"orders": AggCount, "amount": AggSum, "largest": AggMax})
	if len(m) != 3 || m[0].Count != 3 || m[0].Values["amount"] != 45 || m[0].Values["largest"] != 50 || m[2].Keys["branch"] != "hkt" || r.Groups[0].Values["amount"] != 40 {
		t.Fatalf("merge: %+v", m)
	}
	for name, bq := range map[string]ReportQuery{
		"no window":       {Dataset: "sales"},
		"bad dimension":   {From: t0, To: t0.Add(time.Hour), GroupBy: []string{"customer"}},
		"bad filter":      {From: t0, To: t0.Add(time.Hour), Filter: map[string]string{"amount": "1"}},
		"bad measure":     {From: t0, To: t0.Add(time.Hour), Measures: []string{"profit"}},
		"detail, no P5":   {From: t0, To: t0.Add(time.Hour), Detail: true},
		"reversed window": {From: t0.Add(time.Hour), To: t0},
	} {
		if err := ValidateReportQuery(salesDS, &bq); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	for name, ds := range map[string][]ReportDataset{
		"no measure":   {{Name: "x"}},
		"bad agg":      {{Name: "x", Measures: []ReportMeasure{{Name: "m", Agg: "avg"}}}},
		"repeated":     {{Name: "x", Measures: []ReportMeasure{{Name: "m", Agg: AggSum}}}, {Name: "x", Measures: []ReportMeasure{{Name: "m", Agg: AggSum}}}},
		"name clashes": {{Name: "x", Dimensions: []string{"m"}, Measures: []ReportMeasure{{Name: "m", Agg: AggSum}}}},
	} {
		if ValidateReportDatasets(ds) == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func TestReportSource(t *testing.T) {
	p := testpki.New(t)
	_, _, corePair := p.Issue(t, "core", "G")
	f := &fakeGW{}
	cs := httptest.NewUnstartedServer(http.HandlerFunc(f.h))
	cs.TLS = &tls.Config{Certificates: []tls.Certificate{corePair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: p.Pool()}
	cs.StartTLS()
	t.Cleanup(cs.Close)
	mk := func(name, cn, man string) *App {
		cert, key, _ := p.IssueApp(t, name, cn)
		mp := filepath.Join(t.TempDir(), "m.yaml")
		_ = os.WriteFile(mp, []byte(man), 0o644)
		a, err := Start(context.Background(), Options{ManifestPath: mp, InstanceID: strings.Split(cn, ".")[1],
			Core: core.Config{URL: cs.URL, NodeID: "G", CertFile: cert, KeyFile: key, CAFile: p.CAFile}, Logf: t.Logf})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = a.Close(context.Background()) })
		return a
	}
	shop := mk("shop", "shop-app.s1", reportManifest)
	rep := mk("report", "heain-report.r1", strings.ReplaceAll(gwManifest, "gw-app", "heain-report"))
	other := mk("other", "other-app.o1", strings.ReplaceAll(gwManifest, "gw-app", "other-app"))

	var got []ReportQuery
	srv := shop.NewServer()
	if err := srv.HandleReportSource(ReportSource{Datasets: []ReportDataset{salesDS}}); err == nil {
		t.Fatal("a source without Query must be refused")
	}
	if err := srv.HandleReportSource(ReportSource{Datasets: []ReportDataset{salesDS}, Query: func(_ context.Context, q ReportQuery) (ReportResult, error) {
		got = append(got, q)
		return ReportResult{Groups: []ReportGroup{{Keys: map[string]string{"branch": "bkk"}, Count: 7, Values: map[string]float64{"amount": 70}}},
			Rows: []map[string]any{{"amount": 10}, {"amount": 60}}}, nil
	}}); err != nil {
		t.Fatal(err)
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx, l) }()
	base := "https://" + l.Addr().String()
	time.Sleep(50 * time.Millisecond)
	send := func(from *App, method, path, body string) (int, string) {
		cl, err := from.AppClient("shop-app", "s1")
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest(method, base+path, strings.NewReader(body))
		req.Header.Set(HeaderTrace, NewID())
		resp, err := cl.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if c, b := send(rep, "GET", ReportSourceDatasetsPath, ""); c != 200 || !strings.Contains(b, `"name":"sales"`) || !strings.Contains(b, `"agg":"sum"`) {
		t.Fatalf("datasets: %d %s", c, b)
	}
	q := `{"report":"daily","run":"r-1","dataset":"sales","from":"2026-10-01T00:00:00Z","to":"2026-10-02T00:00:00Z","group_by":["branch"]}`
	if c, b := send(rep, "POST", ReportSourceQueryPath, q); c != 200 || !strings.Contains(b, `"count":7`) || strings.Contains(b, `"rows"`) {
		t.Fatalf("query: %d %s", c, b)
	}
	dq := strings.Replace(q, `"group_by"`, `"detail":true,"detail_action":"p5-1","max_rows":1,"group_by"`, 1)
	if c, b := send(rep, "POST", ReportSourceQueryPath, dq); c != 200 || !strings.Contains(b, `"rows":[{"amount":10}]`) || !strings.Contains(b, `"truncated":true`) {
		t.Fatalf("detail: %d %s", c, b)
	}
	if len(got) != 2 || len(got[0].Measures) != 3 || got[1].DetailAction != "p5-1" {
		t.Fatalf("queries: %+v", got)
	}
	for name, c := range map[string]struct {
		from      *App
		method, b string
		path      string
		want      int
	}{
		"another app reads":   {other, "GET", "", ReportSourceDatasetsPath, 403},
		"another app queries": {other, "POST", q, ReportSourceQueryPath, 403},
		"unknown dataset":     {rep, "POST", strings.Replace(q, `"sales"`, `"stock"`, 1), ReportSourceQueryPath, 404},
		"unknown dimension":   {rep, "POST", strings.Replace(q, `["branch"]`, `["customer"]`, 1), ReportSourceQueryPath, 400},
		"detail without P5":   {rep, "POST", strings.Replace(q, `"group_by"`, `"detail":true,"group_by"`, 1), ReportSourceQueryPath, 400},
		"unknown field":       {rep, "POST", strings.Replace(q, `"group_by"`, `"x":1,"group_by"`, 1), ReportSourceQueryPath, 400},
	} {
		if code, b := send(c.from, c.method, c.path, c.b); code != c.want {
			t.Fatalf("%s: %d %s", name, code, b)
		}
	}
	if len(got) != 2 {
		t.Fatalf("a refused query reached the app: %d", len(got))
	}
}
