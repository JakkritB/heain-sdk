package conformance

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/heainframework/heain-sdk/heain"
)

// Phase 2 (G <- S1, G <- W through a proxy; the app runs on W): C10, plus
// C13 and C14 for the cross-node path.
const wNode = "W"

func (d *Driver) mode(base, node string) string {
	_, out := d.as("admin", base, node, "GET", "/health", nil)
	if m := str(jsonMap(out), "mode"); m != "" {
		return m
	}
	return "normal"
}

func (d *Driver) submitAt(base, node, capName, payload string) (int, map[string]any) {
	body := map[string]any{"capability": capName, "payload_b64": []byte(payload), "classification": map[string]any{"delivery": "IMMEDIATE"}}
	st, out := d.call(d.probeHTTP(node), "POST", base+"/v1/app/jobs", body, map[string]string{"Idempotency-Key": "conf-" + heain.NewID()})
	return st, jsonMap(out)
}

func (d *Driver) jobAt(base, node, tk string, timeout time.Duration) map[string]any {
	var m map[string]any
	waitFor(timeout, func() bool {
		_, out := d.probeDo(base, node, "GET", "/v1/app/jobs/"+tk, nil)
		m = jsonMap(out)
		s := str(m, "state")
		return s == "completed" || s == "delivered" || s == "retries_exhausted"
	})
	return m
}

func (d *Driver) offlineAllowed(capName string) bool {
	off := d.Man.Offline
	if off == nil || off.Allowed == nil {
		return true
	}
	for _, c := range off.Allowed {
		if c == capName {
			return true
		}
	}
	return false
}

// RunOffline runs phase 2 (C10).
func (d *Driver) RunOffline(ctx context.Context) {
	defer d.Save()
	d.appBase = fmt.Sprintf("https://127.0.0.1:%d", d.Conf.Port)
	for _, nb := range [][2]string{{gBase2, gNode}, {wBase, wNode}} {
		if !waitFor(120*time.Second, func() bool { st, _ := d.as("admin", nb[0], nb[1], "GET", "/health", nil); return st == 200 }) {
			d.check("C10", "core "+nb[1]+" is up", false, "no /health within 120 s")
			return
		}
	}
	d.setSystem(wBase, wNode, "apps.heartbeat_interval", "3s")
	d.setSystem(wBase, wNode, "apps.ttl", "10s")
	for _, e := range d.Conf.Endpoints {
		d.marker(e.Secret)
	}
	for _, j := range d.Conf.Jobs {
		d.marker(j.Payload)
		d.marker(j.ExpectOutput)
	}
	if _, err := d.probe(ctx, gBase2, gNode, wBase, wNode, "p2", d.probeManifest(false)); err != nil {
		d.check("C10", "the driver's probe app is admitted on W", false, "%v", err)
		return
	}
	if !d.startDeps(gBase2, gNode, wBase, wNode) {
		d.check("C10", "companion apps start on W and are admitted", false, "%d companion(s)", len(d.Conf.Deps))
		return
	}
	if err := d.enrollToken(gBase2, gNode, d.AppReg, filepath.Join(d.Shared, "enroll", "a1.json")); err != nil {
		d.check("C10", "enrolment token issued by G", false, "%v", err)
		return
	}
	d.host("app_start", nil)
	waitFor(90*time.Second, func() bool {
		d.approveWaiting(wBase, wNode, "app.register")
		return d.appStatus(wBase, wNode, d.Man.App.ID, d.Instance) == "active"
	})
	st := d.appStatus(wBase, wNode, d.Man.App.ID, d.Instance)
	d.check("C10", "the app runs on W (enrolled at G, registered with W's core)", st == "active", "status %q", st)
	if st != "active" {
		return
	}
	var allowedJob, deniedJob *JobCase
	for i := range d.Conf.Jobs {
		j := &d.Conf.Jobs[i]
		if d.offlineAllowed(j.Capability) && allowedJob == nil {
			allowedJob = j
		}
		if !d.offlineAllowed(j.Capability) && deniedJob == nil {
			deniedJob = j
		}
	}
	if allowedJob != nil { // a job while connected (its payload crosses W's network only encrypted)
		_, r := d.submitAt(wBase, wNode, allowedJob.Capability, allowedJob.Payload)
		m := d.jobAt(wBase, wNode, str(r, "ticket_id"), 90*time.Second)
		d.check("C10", "connected: a job runs on W", str(m, "state") == "completed" || str(m, "state") == "delivered", "state %s", str(m, "state"))
	}
	time.Sleep(15 * time.Second) // W's escrowed copy of G's state must include the new certificates

	// ---- partition
	d.host("proxy_cut", nil)
	stand := waitFor(90*time.Second, func() bool { return d.mode(wBase, wNode) == "standalone" })
	d.check("C10", "partition (W's only path to G cut) -> W is standalone", stand, "")
	if !stand {
		return
	}
	_, out := d.probeDo(wBase, wNode, "GET", "/v1/app/mode", nil)
	d.check("C10", "the mode change is visible through /v1/app/mode", str(jsonMap(out), "mode") == "standalone", "%s", firstLine(string(out)))
	if allowedJob != nil {
		var m map[string]any
		ok := waitFor(120*time.Second, func() bool {
			s, r := d.submitAt(wBase, wNode, allowedJob.Capability, allowedJob.Payload)
			if s != 202 {
				return false
			}
			m = d.jobAt(wBase, wNode, str(r, "ticket_id"), 40*time.Second)
			return str(m, "state") == "completed" || str(m, "state") == "delivered"
		})
		d.check("C10", "standalone: "+allowedJob.Capability+" (allowed offline) still runs", ok, "state %s", str(m, "state"))
	}
	if deniedJob != nil {
		s, r := d.submitAt(wBase, wNode, deniedJob.Capability, deniedJob.Payload)
		e, _ := r["error"].(map[string]any)
		d.check("C10", "standalone: "+deniedJob.Capability+" (not allowed offline) is refused", s == 409 && str(e, "code") == "standalone_not_allowed", "%d %v", s, str(e, "code"))
	}
	for _, c := range d.Conf.Endpoints {
		_, cp, ok := d.endpointFor(c.Method, c.Path)
		if !ok {
			continue
		}
		r := d.callApp(c, heain.NewID(), cp.Lane)
		if d.offlineAllowed(cp.Name) {
			want := c.Expect
			if want == 0 {
				want = 200
			}
			d.check("C10", fmt.Sprintf("standalone: %s %s (%s allowed offline) is served", c.Method, c.Path, cp.Name), r.status == want, "got %d", r.status)
		} else {
			d.check("C10", fmt.Sprintf("standalone: %s %s (%s not allowed offline) is refused", c.Method, c.Path, cp.Name),
				r.status == 409 && errCode(r.body) == "standalone_not_allowed", "%d %s", r.status, errCode(r.body))
		}
	}
	// the app learns the mode by polling (heain-sdk: every 5 s); then it can journal its own events
	time.Sleep(6 * time.Second)
	for _, c := range d.Conf.Endpoints {
		if _, cp, ok := d.endpointFor(c.Method, c.Path); ok && d.offlineAllowed(cp.Name) {
			d.callApp(c, heain.NewID(), cp.Lane)
		}
	}
	_, jo := d.as("admin", wBase, wNode, "GET", "/v1/admin/journal?limit=10000", nil)
	var j struct {
		Entries []struct {
			Seq    uint64 `json:"seq"`
			Source string `json:"source"`
			Action string `json:"action"`
			Actor  string `json:"actor"`
			Kind   string `json:"kind"`
		} `json:"entries"`
	}
	_ = json.Unmarshal(jo, &j)
	appEv, appSrc := 0, 0
	for _, e := range j.Entries {
		if e.Source == "core" && e.Action == "app.event" && e.Actor == d.AppReg {
			appEv++
		}
		if e.Source == "app" {
			appSrc++
		}
	}
	d.check("C10", "the journal is written while standalone (the app's formal events)", appEv > 0, "%d entries, %d app.event of the app, %d app domain events", len(j.Entries), appEv, appSrc)

	// ---- heal
	d.host("proxy_heal", nil)
	normal := waitFor(180*time.Second, func() bool { return d.mode(wBase, wNode) == "normal" })
	d.check("C10", "reconnect -> W leaves standalone", normal, "")
	_, out = d.probeDo(wBase, wNode, "GET", "/v1/app/mode", nil)
	d.check("C10", "/v1/app/mode shows normal again", str(jsonMap(out), "mode") == "normal", "%s", firstLine(string(out)))
	var vr map[string]any
	acked := waitFor(150*time.Second, func() bool {
		_, b := d.as("admin", wBase, wNode, "GET", "/v1/admin/journal/verify", nil)
		vr = jsonMap(b)
		return vr["ok"] == true && num(vr, "entries") > 0 && num(vr, "acked_through_seq") >= num(vr, "entries")
	})
	d.check("C10", "the journal is reconciled to G (acknowledged through its last entry)", acked, "%v", vr)
	last := uint64(num(vr, "entries"))
	seen := map[uint64]int{}
	appMerged := 0
	for _, e := range d.audit(gBase2, gNode) {
		if e.Action == "journal.merged" && e.Actor == wNode {
			seen[uint64(num(e.Detail, "origin_seq"))]++
			if len(e.Result) > 4 && e.Result[:4] == "app:" {
				appMerged++
			}
		}
	}
	lost, dup := 0, 0
	for s := uint64(1); s <= last; s++ {
		switch seen[s] {
		case 0:
			lost++
		case 1:
		default:
			dup++
		}
	}
	d.check("C10", "reconcile: no lost and no duplicated events (by sequence number)", last > 0 && lost == 0 && dup == 0, "%d entries on W, %d lost, %d duplicated", last, lost, dup)
	d.check("C10", "the app's own journal events reached G", appMerged == appSrc, "%d on W, %d merged on G", appSrc, appMerged)
	d.proxyCheck()
	d.c14(d.DataDirs, "phase 2: G, W and the app")
}
