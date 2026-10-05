package conformance

import (
	"bytes"

	"context"
	"encoding/json"
	"fmt"
	"github.com/heainframework/heain-sdk/manifest"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// RunOptions configure `heain-conformance run`.
type RunOptions struct {
	AppDir  string   // the app under test (conformance.yaml, manifest, its own build/start commands)
	CoreDir string   // heain-core source
	OutDir  string   // where report.json, report.txt and the logs are copied
	Phases  []string // single, offline
	Keep    bool     // keep the work directory
	Log     io.Writer
}

type runner struct {
	o      RunOptions
	conf   Conf
	work   string
	shared string
	node   string // the core binary
	lanIP  string
	phase  string
	cores  map[string]*proc
	coreA  map[string][]string
	app    *proc
	deps   []*proc
	proxy  *scanProxy
	logs   string
}

type proc struct {
	name string
	cmd  *exec.Cmd
	done chan struct{}
	out  *bytes.Buffer
	mu   sync.Mutex
}

// Run builds heain-core and the app, runs the phases and returns the report.
func Run(ctx context.Context, o RunOptions) (*Report, error) {
	r := &runner{o: o}
	var err error
	if r.conf, err = LoadConf(o.AppDir); err != nil {
		return nil, err
	}
	if r.work, err = os.MkdirTemp("", "heain-conformance-"); err != nil {
		return nil, err
	}
	r.shared, r.logs = filepath.Join(r.work, "shared"), filepath.Join(r.work, "logs")
	for _, d := range []string{r.shared + "/app", r.logs} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	r.lanIP = lanAddress()
	r.logf("work directory %s", r.work)
	if err := r.build(ctx); err != nil {
		return nil, err
	}
	for _, ph := range o.Phases {
		if err := r.runPhase(ctx, strings.TrimSpace(ph)); err != nil {
			r.logf("phase %s: %v", ph, err)
		}
	}
	rep := &Report{}
	raw, err := os.ReadFile(filepath.Join(r.shared, "report.json"))
	if err != nil {
		return nil, fmt.Errorf("no report was written: %w", err)
	}
	if err := json.Unmarshal(raw, rep); err != nil {
		return nil, err
	}
	if o.OutDir != "" {
		_ = os.MkdirAll(filepath.Join(o.OutDir, "logs"), 0o755)
		for _, f := range []string{"report.json", "report.txt"} {
			copyFile(filepath.Join(r.shared, f), filepath.Join(o.OutDir, f))
		}
		logs, _ := filepath.Glob(filepath.Join(r.logs, "*"))
		for _, l := range logs {
			copyFile(l, filepath.Join(o.OutDir, "logs", filepath.Base(l)))
		}
	}
	if !o.Keep {
		_ = os.RemoveAll(r.work)
	}
	return rep, nil
}

func (r *runner) logf(f string, a ...any) { fmt.Fprintf(r.o.Log, "heain-conformance: "+f+"\n", a...) }

func (r *runner) sh(ctx context.Context, dir string, env []string, args []string) (string, error) {
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (r *runner) build(ctx context.Context) error {
	r.node = filepath.Join(r.work, "node")
	coreEnv := []string{"GOWORK=off"}
	if v := os.Getenv("CORE_GOFLAGS"); v != "" {
		coreEnv = append(coreEnv, "GOFLAGS="+v)
	}
	r.logf("building heain-core from %s", r.o.CoreDir)
	if out, err := r.sh(ctx, r.o.CoreDir, coreEnv, []string{"go", "build", "-o", r.node, "./cmd/node"}); err != nil {
		return fmt.Errorf("core build: %v\n%s", err, out)
	}
	if len(r.conf.Build) > 0 {
		var env []string
		if v := os.Getenv("SDK_GOWORK"); v != "" { // like the live tests: a Go workspace for SDK-based apps
			env = append(env, "GOWORK="+v, "GOFLAGS=")
		}
		r.logf("building the app: %s", strings.Join(r.conf.Build, " "))
		if out, err := r.sh(ctx, r.o.AppDir, env, r.conf.Build); err != nil {
			return fmt.Errorf("app build: %v\n%s", err, out)
		}
	}
	copyFile(filepath.Join(r.o.AppDir, r.conf.Manifest), filepath.Join(r.shared, "app", "heain-app.yaml"))
	for i, cd := range r.conf.Companions {
		dir := filepath.Join(r.o.AppDir, cd)
		cc, err := LoadConf(dir)
		if err != nil {
			return fmt.Errorf("companion %s: %w", cd, err)
		}
		m, err := manifest.Load(filepath.Join(dir, cc.Manifest))
		if err != nil {
			return fmt.Errorf("companion %s: %w", cd, err)
		}
		if len(cc.Build) > 0 {
			var env []string
			if v := os.Getenv("SDK_GOWORK"); v != "" {
				env = append(env, "GOWORK="+v, "GOFLAGS=")
			}
			r.logf("building companion %s: %s", m.App.ID, strings.Join(cc.Build, " "))
			if out, err := r.sh(ctx, dir, env, cc.Build); err != nil {
				return fmt.Errorf("companion %s build: %v\n%s", cd, err, out)
			}
		}
		r.conf.Deps = append(r.conf.Deps, Dep{Dir: dir, AppID: m.App.ID, Instance: fmt.Sprintf("d%d", i+1), Port: r.conf.Port + 10 + i,
			Manifest: filepath.Join(dir, cc.Manifest), Start: cc.Start})
	}
	raw, _ := json.Marshal(r.conf)
	return os.WriteFile(filepath.Join(r.shared, "app", "conformance.json"), raw, 0o644)
}

func copyFile(from, to string) {
	b, err := os.ReadFile(from)
	if err == nil {
		_ = os.WriteFile(to, b, 0o644)
	}
}

// lanAddress is this machine's first non-loopback IPv4 address (C13: a
// claim sent to core through it does not come from loopback).
func lanAddress() string {
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() {
				return n.IP.String()
			}
		}
	}
	return ""
}

// ---- processes ----

func (r *runner) spawn(name, dir string, env []string, args []string) (*proc, error) {
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	lf, err := os.OpenFile(filepath.Join(r.logs, r.phase+"-"+name+".log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	p := &proc{name: name, cmd: cmd, done: make(chan struct{}), out: &bytes.Buffer{}}
	w := io.MultiWriter(lf, &lockedWriter{p: p})
	cmd.Stdout, cmd.Stderr = w, w
	if err := cmd.Start(); err != nil {
		lf.Close()
		return nil, fmt.Errorf("start %s: %w", name, err)
	}
	go func() { _ = cmd.Wait(); lf.Close(); close(p.done) }()
	return p, nil
}

type lockedWriter struct{ p *proc }

func (l *lockedWriter) Write(b []byte) (int, error) {
	l.p.mu.Lock()
	defer l.p.mu.Unlock()
	if l.p.out.Len() < 1<<20 {
		l.p.out.Write(b)
	}
	return len(b), nil
}

func (p *proc) signal(s syscall.Signal) {
	if p != nil && p.cmd.Process != nil {
		_ = syscall.Kill(-p.cmd.Process.Pid, s)
	}
}

func (p *proc) running() bool {
	if p == nil {
		return false
	}
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

// stop sends SIGTERM to the process group, then SIGKILL after grace.
func (p *proc) stop(grace time.Duration) {
	if !p.running() {
		return
	}
	p.signal(syscall.SIGCONT)
	p.signal(syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(grace):
		p.signal(syscall.SIGKILL)
		<-p.done
	}
}

func (p *proc) exitCode() int {
	if p.cmd.ProcessState == nil {
		return -1
	}
	return p.cmd.ProcessState.ExitCode()
}

// ---- phases ----

func (r *runner) dir(parts ...string) string {
	d := filepath.Join(append([]string{r.work, r.phase}, parts...)...)
	_ = os.MkdirAll(d, 0o700)
	return d
}

func (r *runner) coreArgs(id, tier string, port, raft int, extra ...string) []string {
	d, c := r.dir(id), filepath.Join(r.shared, "certs")
	a := []string{r.node, "-node-id=" + id, "-tier=" + tier, "-raft-addr=127.0.0.1:" + strconv.Itoa(raft), "-data-dir=" + d,
		"-http-addr=127.0.0.1:" + strconv.Itoa(port), "-cert=" + c + "/" + id + ".pem", "-key=" + c + "/" + id + ".key", "-ca=" + c + "/ca.pem",
		"-admin-node-id=admin", "-approver-ids=approver-1",
		"-ingest-queue-path=" + d + "/queue.db", "-staging-path=" + d + "/staging.db", "-approval-store-path=" + d + "/approvals.db"}
	return append(a, extra...)
}

func (r *runner) worker(id string, port, raft, promote int, parent string) []string {
	return r.coreArgs(id, "WORKER", port, raft, "-bootstrap=false", "-parent-addr="+parent+"/health", "-parent-node-id=G",
		"-promote-raft-addr=127.0.0.1:"+strconv.Itoa(promote), "-promote-data-dir="+r.dir(id, "promote"),
		"-farm-register-addr="+parent, "-farm-register-node-id=G", "-self-addr=https://127.0.0.1:"+strconv.Itoa(port), "-farm-register-interval=2s")
}

func (r *runner) startCore(id string, args []string) error {
	p, err := r.spawn(id, r.work, nil, args)
	if err != nil {
		return err
	}
	r.cores[id], r.coreA[id] = p, args
	return nil
}

func (r *runner) appEnv(coreID string, corePort int, enrollPort int) []string {
	c := filepath.Join(r.shared, "certs")
	port := strconv.Itoa(r.conf.Port)
	return []string{"HEAIN_MANIFEST=" + filepath.Join(r.shared, "app", "heain-app.yaml"), "HEAIN_INSTANCE=a1",
		"HEAIN_CORE_URL=https://127.0.0.1:" + strconv.Itoa(corePort), "HEAIN_CORE_ID=" + coreID,
		"HEAIN_CA=" + c + "/ca.pem", "HEAIN_CHAIN=" + c + "/prov.pem", "HEAIN_STATE_DIR=" + r.dir("app-state"),
		"HEAIN_ENROLL_TOKEN=" + filepath.Join(r.shared, "enroll", "a1.json"),
		"HEAIN_ENROLL_CORE_URL=https://127.0.0.1:" + strconv.Itoa(enrollPort), "HEAIN_ENROLL_CORE_ID=G",
		"HEAIN_ENDPOINT_BASE=https://127.0.0.1:" + port, "HEAIN_LISTEN=127.0.0.1:" + port}
}

func (r *runner) runPhase(ctx context.Context, phase string) error {
	r.phase, r.cores, r.coreA, r.app, r.proxy = phase, map[string]*proc{}, map[string][]string{}, nil, nil
	for _, d := range []string{"certs", "enroll", "probe-p1", "probe-p2"} {
		_ = os.RemoveAll(filepath.Join(r.shared, d))
	}
	_ = os.MkdirAll(filepath.Join(r.shared, "enroll"), 0o755)
	_ = os.Remove(filepath.Join(r.shared, "markers.txt"))
	r.logf("phase %s: starting", phase)
	defer func() {
		r.app.stop(30 * time.Second)
		for _, p := range r.deps {
			p.stop(30 * time.Second)
		}
		r.deps = nil
		for _, p := range r.cores {
			p.stop(15 * time.Second)
		}
		if r.proxy != nil {
			r.proxy.close()
		}
	}()
	var appEnv []string
	var dataDirs []string
	switch phase {
	case "single":
		if err := PKI(r.shared, map[string]string{"G": r.lanOr()}); err != nil {
			return err
		}
		listen := "0.0.0.0" // reachable through the LAN address too (C13)
		args := r.coreArgs("G", "GLOBAL_PRIMARY", gPort, gPort+1, "-bootstrap=true",
			"-broadcast-topology-file="+filepath.Join(r.shared, "topology.json"), "-broadcast-global-addr="+gBase, "-broadcast-global-node-id=G",
			"-provision-ca-cert="+filepath.Join(r.shared, "certs", "prov.pem"), "-provision-ca-key="+filepath.Join(r.shared, "certs", "prov.key"))
		for i, a := range args {
			if strings.HasPrefix(a, "-http-addr=") {
				args[i] = "-http-addr=" + listen + ":" + strconv.Itoa(gPort)
			}
		}
		if err := r.startCore("G", args); err != nil {
			return err
		}
		appEnv = r.appEnv("G", gPort, gPort)
		dataDirs = []string{r.dir("G"), r.dir("app-state")}
	case "offline":
		if err := PKI(r.shared, map[string]string{"G": "127.0.0.1", "S1": "127.0.0.1", "W": "127.0.0.1"}); err != nil {
			return err
		}
		r.proxy = newScanProxy(fmt.Sprintf("127.0.0.1:%d", proxyPort), fmt.Sprintf("127.0.0.1:%d", gPort), filepath.Join(r.shared, "markers.txt"))
		if err := r.startCore("G", r.coreArgs("G", "ZONE", gPort, gPort+1, "-bootstrap=true", "-farm-registry-ttl=30s",
			"-provision-ca-cert="+filepath.Join(r.shared, "certs", "prov.pem"), "-provision-ca-key="+filepath.Join(r.shared, "certs", "prov.key"))); err != nil {
			return err
		}
		time.Sleep(3 * time.Second)
		if err := r.startCore("S1", r.worker("S1", s1Port, s1Port+1, s1Port+2, gBase)); err != nil {
			return err
		}
		if err := r.startCore("W", r.worker("W", wPort, wPort+5, wPort+6, fmt.Sprintf("https://127.0.0.1:%d", proxyPort))); err != nil {
			return err
		}
		appEnv = r.appEnv("W", wPort, gPort)
		dataDirs = []string{r.dir("G"), r.dir("W"), r.dir("S1"), r.dir("app-state")}
	default:
		return fmt.Errorf("unknown phase %q (single, offline)", phase)
	}
	for _, dd := range r.conf.DataDirs {
		dataDirs = append(dataDirs, filepath.Join(r.o.AppDir, dd))
	}
	d, err := NewDriver(r.shared)
	if err != nil {
		return err
	}
	d.DataDirs = dataDirs
	d.Host = func(action string, args map[string]string) HostResult { return r.action(action, args, appEnv) }
	log.SetOutput(&prefixWriter{w: r.o.Log, prefix: "  [" + phase + "] "})
	log.SetFlags(log.Ltime)
	switch phase {
	case "single":
		d.RunSingle(ctx)
	case "offline":
		d.RunOffline(ctx)
	}
	return nil
}

func (r *runner) lanOr() string {
	if r.lanIP != "" {
		return r.lanIP
	}
	return "127.0.0.1"
}

type prefixWriter struct {
	w      io.Writer
	prefix string
}

func (p *prefixWriter) Write(b []byte) (int, error) {
	for _, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		fmt.Fprintf(p.w, "%s%s\n", p.prefix, l)
	}
	return len(b), nil
}

// action performs what the driver asks of the host.
func (r *runner) action(action string, args map[string]string, appEnv []string) HostResult {
	switch action {
	case "app_start":
		if r.app.running() {
			return HostResult{OK: true}
		}
		p, err := r.spawn("app", r.o.AppDir, appEnv, r.conf.Start)
		if err != nil {
			return HostResult{Out: err.Error(), Exit: 1}
		}
		r.app = p
		return HostResult{OK: true}
	case "deps_start":
		for _, dp := range r.conf.Deps {
			port := strconv.Itoa(dp.Port)
			env := append(append([]string{}, appEnv...), "HEAIN_MANIFEST="+dp.Manifest, "HEAIN_INSTANCE="+dp.Instance,
				"HEAIN_STATE_DIR="+r.dir(dp.Instance+"-state"), "HEAIN_ENROLL_TOKEN="+filepath.Join(r.shared, "enroll", dp.Instance+".json"),
				"HEAIN_ENDPOINT_BASE=https://127.0.0.1:"+port, "HEAIN_LISTEN=127.0.0.1:"+port)
			p, err := r.spawn(dp.AppID+"-"+dp.Instance, dp.Dir, env, dp.Start)
			if err != nil {
				return HostResult{Out: err.Error(), Exit: 1}
			}
			r.deps = append(r.deps, p)
		}
		return HostResult{OK: true}
	case "app_stop":
		r.app.stop(30 * time.Second)
		return HostResult{OK: true}
	case "app_pause":
		r.app.signal(syscall.SIGSTOP)
		return HostResult{OK: true}
	case "app_unpause":
		r.app.signal(syscall.SIGCONT)
		return HostResult{OK: true}
	case "app_broken":
		env := append(append([]string{}, appEnv...), "HEAIN_MANIFEST="+args["manifest"], "HEAIN_INSTANCE=c1x",
			"HEAIN_STATE_DIR="+r.dir("c1x"), "HEAIN_ENROLL_TOKEN="+filepath.Join(r.shared, "enroll", "none.json"), "HEAIN_ENROLL_WAIT=5s")
		p, err := r.spawn("app-broken", r.o.AppDir, env, r.conf.Start)
		if err != nil {
			return HostResult{Out: err.Error(), Exit: 1}
		}
		select {
		case <-p.done:
		case <-time.After(60 * time.Second):
			p.stop(5 * time.Second)
			return HostResult{Out: "still running after 60 s", Exit: 0}
		}
		p.mu.Lock()
		out := p.out.String()
		p.mu.Unlock()
		return HostResult{OK: p.exitCode() == 0, Exit: p.exitCode(), Out: out}
	case "core_restart":
		g := r.cores["G"]
		g.stop(20 * time.Second)
		a := append([]string{}, r.coreA["G"]...)
		if e := args["extra"]; e != "" {
			a = append(a, e)
		}
		p, err := r.spawn("G", r.work, nil, a)
		if err != nil {
			return HostResult{Out: err.Error(), Exit: 1}
		}
		r.cores["G"] = p
		return HostResult{OK: true}
	case "remote_claim":
		if r.lanIP == "" {
			return HostResult{Exit: 2, Out: "this machine has no non-loopback address to claim from"}
		}
		code, body, err := RemoteClaim(r.shared, fmt.Sprintf("https://%s:%d", r.lanIP, gPort))
		out := fmt.Sprintf("claim through %s: %d %s %v", r.lanIP, code, strings.TrimSpace(body), err)
		if code == 403 && strings.Contains(body, "locality_violation") {
			return HostResult{OK: true, Exit: 0, Out: out}
		}
		return HostResult{Exit: 1, Out: out}
	case "proxy_cut":
		r.proxy.cut()
		return HostResult{OK: true}
	case "proxy_heal":
		r.proxy.heal()
		return HostResult{OK: true}
	case "proxy_hits":
		b, hits := r.proxy.stats()
		n := 0
		for _, v := range hits {
			n += v
		}
		return HostResult{OK: b > 0 && n == 0, Out: fmt.Sprintf("%d bytes passed, %d marker hits %v", b, n, hits)}
	}
	return HostResult{Out: "unknown action " + action, Exit: 1}
}

// ---- the proxy between W and G (C10 cut/heal, C13 inspection) ----

type scanProxy struct {
	listen, target, markersFile string
	mu                          sync.Mutex
	ln                          net.Listener
	conns                       map[net.Conn]bool
	bytes                       int64
	hits                        map[string]int
}

func newScanProxy(listen, target, markersFile string) *scanProxy {
	p := &scanProxy{listen: listen, target: target, markersFile: markersFile, conns: map[net.Conn]bool{}, hits: map[string]int{}}
	p.heal()
	return p
}

func (p *scanProxy) heal() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ln != nil {
		return
	}
	l, err := net.Listen("tcp", p.listen)
	if err != nil {
		log.Printf("proxy: %v", err)
		return
	}
	p.ln = l
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go p.serve(c)
		}
	}()
}

func (p *scanProxy) serve(c net.Conn) {
	u, err := net.DialTimeout("tcp", p.target, 5*time.Second)
	if err != nil {
		c.Close()
		return
	}
	p.mu.Lock()
	p.conns[c], p.conns[u] = true, true
	p.mu.Unlock()
	done := make(chan struct{}, 2)
	go func() { p.copyScan(u, c); done <- struct{}{} }()
	go func() { p.copyScan(c, u); done <- struct{}{} }()
	<-done
	c.Close()
	u.Close()
	p.mu.Lock()
	delete(p.conns, c)
	delete(p.conns, u)
	p.mu.Unlock()
}

func (p *scanProxy) markers() [][]byte {
	raw, _ := os.ReadFile(p.markersFile)
	var ms [][]byte
	for _, l := range strings.Split(string(raw), "\n") {
		if l = strings.TrimSpace(l); len(l) >= 6 {
			ms = append(ms, []byte(l))
		}
	}
	return ms
}

// copyScan copies src to dst and looks for every marker in the stream
// (across read boundaries).
func (p *scanProxy) copyScan(dst, src net.Conn) {
	buf := make([]byte, 32*1024)
	var tail []byte
	ms, loaded := p.markers(), time.Now()
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if time.Since(loaded) > time.Second {
				ms, loaded = p.markers(), time.Now()
			}
			win := append(tail, buf[:n]...)
			p.mu.Lock()
			p.bytes += int64(n)
			for _, m := range ms {
				if bytes.Contains(win, m) {
					p.hits[string(m)]++
				}
			}
			p.mu.Unlock()
			if len(win) > 256 {
				tail = append([]byte(nil), win[len(win)-256:]...)
			} else {
				tail = win
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (p *scanProxy) cut() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ln != nil {
		p.ln.Close()
		p.ln = nil
	}
	for c := range p.conns {
		c.Close()
	}
	p.conns = map[net.Conn]bool{}
}

func (p *scanProxy) close() { p.cut() }

func (p *scanProxy) stats() (int64, map[string]int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	h := map[string]int{}
	for k, v := range p.hits {
		h[k] = v
	}
	return p.bytes, h
}
