package conformance

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// RunOptions configure `heain-conformance run`.
type RunOptions struct {
	AppDir  string   // the app under test (Dockerfile, conformance.yaml, manifest)
	CoreDir string   // heain-core source (built with CGO_ENABLED=0)
	SDKDir  string   // heain-sdk source (for the harness tool binary)
	OutDir  string   // where report.json / report.txt / logs are copied
	Phases  []string // single, offline
	Keep    bool     // leave containers and the work directory
	Log     io.Writer
}

type runner struct {
	o       RunOptions
	conf    Conf
	work    string
	shared  string
	tag     string
	project string
	file    string
	env     []string
}

// Run builds everything, runs the phases and returns the report.
func Run(ctx context.Context, o RunOptions) (*Report, error) {
	r := &runner{o: o, tag: strconv.FormatInt(time.Now().Unix(), 36)}
	r.env = r.common()
	var err error
	if r.conf, err = LoadConf(o.AppDir); err != nil {
		return nil, err
	}
	if r.work, err = os.MkdirTemp("", "heain-conformance-"); err != nil {
		return nil, err
	}
	r.shared = filepath.Join(r.work, "shared")
	for _, d := range []string{"build/core", "build/tool", "shared/app", "shared/ctl", "shared/enroll", "shared/logs"} {
		if err := os.MkdirAll(filepath.Join(r.work, d), 0o755); err != nil {
			return nil, err
		}
	}
	r.logf("work directory %s", r.work)
	if err := r.build(ctx); err != nil {
		return nil, err
	}
	for _, ph := range o.Phases {
		if err := r.phase(ctx, ph); err != nil {
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
		logs, _ := filepath.Glob(filepath.Join(r.shared, "logs", "*"))
		for _, l := range logs {
			copyFile(l, filepath.Join(o.OutDir, "logs", filepath.Base(l)))
		}
	}
	if !o.Keep {
		_ = os.RemoveAll(r.work)
		for _, n := range []string{"core", "tool", "app"} {
			_, _ = r.sh(context.Background(), "", nil, "docker", "image", "rm", "-f", r.image(n))
		}
	}
	return rep, nil
}

func (r *runner) logf(f string, a ...any) { fmt.Fprintf(r.o.Log, "heain-conformance: "+f+"\n", a...) }

func (r *runner) sh(ctx context.Context, dir string, env []string, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// build: static binaries, FROM scratch images, the app image.
func (r *runner) build(ctx context.Context) error {
	static := []string{"CGO_ENABLED=0", "GOOS=linux"}
	coreEnv := append(append([]string{}, static...), "GOWORK=off")
	if v := os.Getenv("CORE_GOFLAGS"); v != "" {
		coreEnv = append(coreEnv, "GOFLAGS="+v)
	}
	if v := os.Getenv("SDK_GOWORK"); v != "" { // like the live tests: a workspace for the SDK build
		static = append(static, "GOWORK="+v, "GOFLAGS=")
	}
	r.logf("building heain-core from %s", r.o.CoreDir)
	if out, err := r.sh(ctx, r.o.CoreDir, coreEnv, "go", "build", "-o", filepath.Join(r.work, "build/core/node"), "./cmd/node"); err != nil {
		return fmt.Errorf("core build: %v\n%s", err, out)
	}
	r.logf("building the harness tool from %s", r.o.SDKDir)
	if out, err := r.sh(ctx, r.o.SDKDir, static, "go", "build", "-o", filepath.Join(r.work, "build/tool/hc"), "./conformance/cmd/heain-conformance"); err != nil {
		return fmt.Errorf("tool build: %v\n%s", err, out)
	}
	_ = os.WriteFile(filepath.Join(r.work, "build/core/Dockerfile"), []byte("FROM scratch\nCOPY node /node\nENTRYPOINT [\"/node\"]\n"), 0o644)
	_ = os.WriteFile(filepath.Join(r.work, "build/tool/Dockerfile"), []byte("FROM scratch\nCOPY hc /hc\nENTRYPOINT [\"/hc\"]\n"), 0o644)
	for name, dir := range map[string]string{"core": "build/core", "tool": "build/tool"} {
		if out, err := r.sh(ctx, r.work, nil, "docker", "build", "-q", "-t", "heain-conf-"+name+":"+r.tag, dir); err != nil {
			return fmt.Errorf("docker build %s: %v\n%s", name, err, out)
		}
	}
	if len(r.conf.Prebuild) > 0 {
		r.logf("app prebuild: %s", strings.Join(r.conf.Prebuild, " "))
		if out, err := r.sh(ctx, r.o.AppDir, static, r.conf.Prebuild[0], r.conf.Prebuild[1:]...); err != nil {
			return fmt.Errorf("app prebuild: %v\n%s", err, out)
		}
	}
	r.logf("building the app image from %s", r.o.AppDir)
	if out, err := r.sh(ctx, r.o.AppDir, nil, "docker", "build", "-q", "-t", "heain-conf-app:"+r.tag, "."); err != nil {
		return fmt.Errorf("app docker build: %v\n%s", err, out)
	}
	copyFile(filepath.Join(r.o.AppDir, r.conf.Manifest), filepath.Join(r.shared, "app", "heain-app.yaml"))
	raw, _ := json.Marshal(r.conf)
	return os.WriteFile(filepath.Join(r.shared, "app", "conformance.json"), raw, 0o644)
}

func copyFile(from, to string) {
	b, err := os.ReadFile(from)
	if err == nil {
		_ = os.WriteFile(to, b, 0o644)
	}
}

// ---- compose ----

type svc = map[string]any

func (r *runner) image(n string) string { return "heain-conf-" + n + ":" + r.tag }

func (r *runner) common() []string {
	return []string{fmt.Sprintf("HOST_UID=%d", os.Getuid()), fmt.Sprintf("HOST_GID=%d", os.Getgid())}
}

func netns(ip string) svc {
	return svc{"command": []string{"hold"}, "networks": svc{"hc": svc{"ipv4_address": ip}}}
}

func coreArgs(id, tier, ip string, extra ...string) []string {
	a := []string{"-node-id=" + id, "-tier=" + tier, "-raft-addr=" + ip + ":19000", "-data-dir=/data", "-http-addr=0.0.0.0:18000",
		"-cert=/shared/certs/" + id + ".pem", "-key=/shared/certs/" + id + ".key", "-ca=/shared/certs/ca.pem",
		"-admin-node-id=admin", "-approver-ids=approver-1",
		"-ingest-queue-path=/data/queue.db", "-staging-path=/data/staging.db", "-approval-store-path=/data/approvals.db"}
	return append(a, extra...)
}

func (r *runner) compose(phase string) map[string]any {
	shared := r.shared + ":/shared"
	tool := func(s svc) svc {
		s["image"] = r.image("tool")
		s["environment"] = r.common()
		if _, ok := s["volumes"]; !ok {
			s["volumes"] = []string{shared}
		}
		return s
	}
	coreSvc := func(id, ns string, args []string, vol string) svc {
		return svc{"image": r.image("core"), "network_mode": "service:" + ns, "command": args, "tmpfs": []string{"/tmp"},
			"volumes":    []string{vol + ":/data", r.shared + ":/shared:ro"},
			"depends_on": svc{"pki": svc{"condition": "service_completed_successfully"}, ns: svc{"condition": "service_started"}}}
	}
	port := strconv.Itoa(r.conf.Port)
	appEnv := func(nodeIP, coreID, enrollURL, enrollID string) []string {
		return []string{"HEAIN_MANIFEST=/shared/app/heain-app.yaml", "HEAIN_INSTANCE=a1", "HEAIN_CORE_URL=https://127.0.0.1:18000", "HEAIN_CORE_ID=" + coreID,
			"HEAIN_CA=/shared/certs/ca.pem", "HEAIN_CHAIN=/shared/certs/prov.pem", "HEAIN_STATE_DIR=/state", "HEAIN_ENROLL_TOKEN=/shared/enroll/a1.json",
			"HEAIN_ENROLL_CORE_URL=" + enrollURL, "HEAIN_ENROLL_CORE_ID=" + enrollID,
			"HEAIN_ENDPOINT_BASE=https://" + nodeIP + ":" + port, "HEAIN_LISTEN=0.0.0.0:" + port}
	}
	services := svc{}
	vols := svc{"app-state": svc{}}
	switch phase {
	case "single":
		services["pki"] = tool(svc{"command": []string{"pki", "-out", "/shared", "-nodes", "G=" + gIP}, "network_mode": "none"})
		services["netns-g"] = tool(netns(gIP))
		services["g"] = coreSvc("G", "netns-g", coreArgs("G", "GLOBAL_PRIMARY", gIP, "-bootstrap=true",
			"-broadcast-topology-file=/shared/topology.json", "-broadcast-global-addr=https://"+gIP+":18000", "-broadcast-global-node-id=G",
			"-provision-ca-cert=/shared/certs/prov.pem", "-provision-ca-key=/shared/certs/prov.key", "${G_EXTRA:--compat-test-probe=false}"), "g-data")
		services["capture"] = tool(svc{"command": []string{"capture", "-iface", "eth0", "-markers", "/shared/markers.txt", "-out", "/shared/capture-g.json"},
			"network_mode": "service:netns-g", "cap_add": []string{"NET_RAW"}, "depends_on": []string{"netns-g"}})
		services["app"] = svc{"image": r.image("app"), "network_mode": "service:netns-g", "environment": appEnv(gIP, "G", "https://127.0.0.1:18000", "G"),
			"volumes": []string{"app-state:/state", r.shared + ":/shared:ro"}, "tmpfs": []string{"/tmp"}, "profiles": []string{"app"}, "stop_grace_period": "30s"}
		services["driver"] = tool(svc{"command": []string{"driver", "-phase", "single", "-shared", "/shared"}, "network_mode": "service:netns-g",
			"volumes": []string{shared, "g-data:/inspect/core:ro", "app-state:/inspect/app:ro"}, "profiles": []string{"driver"}})
		services["remote"] = tool(svc{"command": []string{"remote-claim", "-shared", "/shared", "-core", "https://" + gIP + ":18000"},
			"networks": svc{"hc": svc{"ipv4_address": "10.77.0.30"}}, "profiles": []string{"remote"}})
		vols["g-data"] = svc{}
	case "offline":
		services["pki"] = tool(svc{"command": []string{"pki", "-out", "/shared", "-nodes", "G=" + gIP + ",S1=10.77.0.11,W=" + wIP}, "network_mode": "none"})
		services["netns-g"] = tool(netns(gIP))
		services["netns-s1"] = tool(netns("10.77.0.11"))
		services["netns-w"] = tool(netns(wIP))
		services["g"] = coreSvc("G", "netns-g", coreArgs("G", "ZONE", gIP, "-bootstrap=true", "-farm-registry-ttl=30s",
			"-provision-ca-cert=/shared/certs/prov.pem", "-provision-ca-key=/shared/certs/prov.key"), "g-data")
		worker := func(id, ip, parent string) []string {
			return coreArgs(id, "WORKER", ip, "-bootstrap=false", "-parent-addr="+parent+"/health", "-parent-node-id=G",
				"-promote-raft-addr="+ip+":19001", "-promote-data-dir=/data/promote", "-farm-register-addr="+parent, "-farm-register-node-id=G",
				"-self-addr=https://"+ip+":18000", "-farm-register-interval=2s")
		}
		services["s1"] = coreSvc("S1", "netns-s1", worker("S1", "10.77.0.11", "https://"+gIP+":18000"), "s1-data")
		services["proxy"] = tool(svc{"command": []string{"proxy", "-listen", "0.0.0.0:28000", "-to", gIP + ":18000", "-state", "/shared/proxy.state"},
			"networks": svc{"hc": svc{"ipv4_address": "10.77.0.13"}}})
		services["w"] = coreSvc("W", "netns-w", worker("W", wIP, "https://10.77.0.13:28000"), "w-data")
		services["capture"] = tool(svc{"command": []string{"capture", "-iface", "eth0", "-markers", "/shared/markers.txt", "-out", "/shared/capture-w.json"},
			"network_mode": "service:netns-w", "cap_add": []string{"NET_RAW"}, "depends_on": []string{"netns-w"}})
		services["app"] = svc{"image": r.image("app"), "network_mode": "service:netns-w", "environment": appEnv(wIP, "W", "https://"+gIP+":18000", "G"),
			"volumes": []string{"app-state:/state", r.shared + ":/shared:ro"}, "tmpfs": []string{"/tmp"}, "profiles": []string{"app"}, "stop_grace_period": "30s"}
		services["driver"] = tool(svc{"command": []string{"driver", "-phase", "offline", "-shared", "/shared"}, "network_mode": "service:netns-w",
			"volumes": []string{shared, "g-data:/inspect/g:ro", "w-data:/inspect/w:ro", "app-state:/inspect/app:ro"}, "profiles": []string{"driver"}})
		vols["g-data"], vols["s1-data"], vols["w-data"] = svc{}, svc{}, svc{}
	}
	return map[string]any{"name": r.project, "services": services, "volumes": vols,
		"networks": svc{"hc": svc{"ipam": svc{"config": []svc{{"subnet": "10.77.0.0/24"}}}}}}
}

func (r *runner) dc(ctx context.Context, env []string, args ...string) (string, error) {
	a := append([]string{"compose", "-p", r.project, "-f", r.file}, args...)
	return r.sh(ctx, r.work, append(r.env, env...), "docker", a...)
}

// phase runs one compose project with its driver, answering its host actions.
func (r *runner) phase(ctx context.Context, phase string) error {
	r.project = "heain-conf-" + phase + "-" + r.tag
	r.file = filepath.Join(r.work, phase+".compose.yaml")
	raw, _ := yaml.Marshal(r.compose(phase))
	if err := os.WriteFile(r.file, raw, 0o644); err != nil {
		return err
	}
	_ = os.WriteFile(filepath.Join(r.shared, "proxy.state"), []byte("up"), 0o644)
	ctls, _ := filepath.Glob(filepath.Join(r.shared, "ctl", "*"))
	for _, f := range ctls {
		_ = os.Remove(f)
	}
	_ = os.RemoveAll(filepath.Join(r.shared, "enroll"))
	_ = os.MkdirAll(filepath.Join(r.shared, "enroll"), 0o755)
	_ = os.RemoveAll(filepath.Join(r.shared, "certs"))
	probes, _ := filepath.Glob(filepath.Join(r.shared, "probe-*"))
	for _, p := range probes {
		_ = os.RemoveAll(p)
	}
	r.logf("phase %s: starting (%s)", phase, r.project)
	defer func() {
		for _, s := range []string{"g", "s1", "w", "app", "proxy"} {
			if out, err := r.dc(context.Background(), nil, "logs", "--no-color", s); err == nil && strings.TrimSpace(out) != "" {
				_ = os.WriteFile(filepath.Join(r.shared, "logs", phase+"-"+s+".log"), []byte(out), 0o644)
			}
		}
		if !r.o.Keep {
			_, _ = r.dc(context.Background(), nil, "--profile", "app", "--profile", "driver", "--profile", "remote", "down", "-v", "--remove-orphans", "-t", "5")
		}
	}()
	if out, err := r.dc(ctx, nil, "up", "-d"); err != nil {
		return fmt.Errorf("compose up: %v\n%s", err, out)
	}
	driver := exec.CommandContext(ctx, "docker", "compose", "-p", r.project, "-f", r.file, "run", "--rm", "--no-deps", "driver")
	driver.Dir, driver.Env = r.work, append(os.Environ(), r.env...)
	pr, pw := io.Pipe()
	driver.Stdout, driver.Stderr = pw, pw
	go func() {
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			fmt.Fprintf(r.o.Log, "  [%s] %s\n", phase, sc.Text())
		}
	}()
	if err := driver.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- driver.Wait(); pw.Close() }()
	served := map[string]bool{}
	for {
		select {
		case err := <-done:
			r.serveActions(ctx, served) // late requests
			return err
		case <-time.After(300 * time.Millisecond):
			r.serveActions(ctx, served)
		}
	}
}

func (r *runner) serveActions(ctx context.Context, served map[string]bool) {
	reqs, _ := filepath.Glob(filepath.Join(r.shared, "ctl", "*.req"))
	sort.Strings(reqs)
	for _, f := range reqs {
		if served[f] {
			continue
		}
		served[f] = true
		var q struct {
			Action string            `json:"action"`
			Args   map[string]string `json:"args"`
		}
		raw, _ := os.ReadFile(f)
		_ = json.Unmarshal(raw, &q)
		res := r.action(ctx, q.Action, q.Args)
		out, _ := json.Marshal(res)
		_ = os.WriteFile(strings.TrimSuffix(f, ".req")+".res", out, 0o644)
	}
}

func (r *runner) action(ctx context.Context, action string, args map[string]string) HostResult {
	r.logf("host action: %s %v", action, args)
	run := func(timeout time.Duration, env []string, a ...string) HostResult {
		c, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		out, err := r.dc(c, env, a...)
		code := 0
		if err != nil {
			code = 1
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			}
		}
		return HostResult{OK: err == nil, Exit: code, Out: out}
	}
	switch action {
	case "app_start":
		return run(2*time.Minute, nil, "up", "-d", "--no-deps", "app")
	case "app_stop":
		return run(time.Minute, nil, "stop", "-t", "30", "app")
	case "app_pause":
		return run(time.Minute, nil, "pause", "app")
	case "app_unpause":
		return run(time.Minute, nil, "unpause", "app")
	case "app_broken":
		return run(90*time.Second, nil, "run", "--rm", "--no-deps", "-e", "HEAIN_MANIFEST="+args["manifest"], "-e", "HEAIN_INSTANCE=c1x",
			"-e", "HEAIN_STATE_DIR=/tmp/c1x", "-e", "HEAIN_ENROLL_TOKEN=/shared/enroll/none.json", "-e", "HEAIN_ENROLL_WAIT=5s", "app")
	case "remote_claim":
		return run(2*time.Minute, nil, "run", "--rm", "--no-deps", "remote")
	case "core_restart":
		return run(3*time.Minute, []string{"G_EXTRA=" + args["extra"]}, "up", "-d", "--no-deps", "--force-recreate", "g")
	}
	return HostResult{Out: "unknown action " + action}
}
