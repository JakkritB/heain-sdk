package conformance

// Apps packaged as container images (CineNexus Pro case study, step 2a,
// 2026-10-09). Docker stays optional (author decision 2026-10-06): an app
// may still start with any command, `docker run ...` included. With a
// `container:` block the suite runs the image itself, so the host actions
// keep their meaning inside a container:
//
//   - the work directory is mounted at the same path, so every HEAIN_*
//     path the suite hands out is valid inside the container;
//   - the container shares the host network (core and the app talk over
//     loopback, as on a node) and runs as the calling user, so the files
//     it writes stay the suite's to inspect and remove;
//   - SIGTERM / SIGKILL become `kill`, SIGSTOP / SIGCONT become `pause` /
//     `unpause` (a stopped `docker run` client would not freeze the app);
//   - every container carries the label heain.conformance=<pid> and is
//     removed when the run ends, so nothing of other projects on the same
//     engine is touched.
//
// The engine is `docker` unless HEAIN_CONTAINER_ENGINE names another with
// the same command line (podman).

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// Container is the `container:` block of conformance.yaml.
type Container struct {
	// Image is the image to run (and the tag to build when Dockerfile is set).
	Image string `yaml:"image" json:"image"`
	// Dockerfile, relative to the app directory: the suite builds Image
	// from it before the tests. Without it, Image must already exist.
	Dockerfile string `yaml:"dockerfile,omitempty" json:"dockerfile,omitempty"`
	// Context is the build context, relative to the app directory (default ".").
	Context string `yaml:"context,omitempty" json:"context,omitempty"`
	// RunArgs are extra `run` arguments, for example [--gpus, all].
	RunArgs []string `yaml:"run_args,omitempty" json:"run_args,omitempty"`
}

func containerEngine() string {
	if e := os.Getenv("HEAIN_CONTAINER_ENGINE"); e != "" {
		return e
	}
	return "docker"
}

var containerSeq atomic.Int64

var unsafeName = regexp.MustCompile(`[^a-zA-Z0-9_.-]+`)

// buildImage builds c.Image in dir when the block names a Dockerfile, or
// checks that the image exists.
func (r *runner) buildImage(ctx context.Context, dir string, c *Container) error {
	eng := containerEngine()
	if c.Dockerfile == "" {
		if out, err := r.sh(ctx, dir, nil, []string{eng, "image", "inspect", "--format", "{{.Id}}", c.Image}); err != nil {
			return fmt.Errorf("container image %s not found and no dockerfile to build it: %v\n%s", c.Image, err, out)
		}
		return nil
	}
	bctx := c.Context
	if bctx == "" {
		bctx = "."
	}
	r.logf("building the container image %s (%s %s, context %s)", c.Image, eng, c.Dockerfile, bctx)
	out, err := r.sh(ctx, dir, nil, []string{eng, "build", "-t", c.Image, "-f", filepath.Join(dir, c.Dockerfile),
		"--label", "heain.conformance.image=1", filepath.Join(dir, bctx)})
	if err != nil {
		return fmt.Errorf("container build: %v\n%s", err, out)
	}
	return nil
}

// containerArgs is the `run` command for c with env (KEY=VALUE, passed by
// name so values stay out of the process list); cmd overrides the image's
// command when not empty. It returns the command and the container name.
func (r *runner) containerArgs(name string, c *Container, env []string, cmd []string) ([]string, string) {
	cn := fmt.Sprintf("heain-conf-%d-%d-%s", os.Getpid(), containerSeq.Add(1), unsafeName.ReplaceAllString(name, "-"))
	a := []string{containerEngine(), "run", "--rm", "--init", "--name", cn,
		"--label", "heain.conformance=" + strconv.Itoa(os.Getpid()),
		"--network", "host", "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"-e", "HOME=/tmp", "-v", r.work + ":" + r.work}
	mounted := map[string]bool{r.work: true}
	for _, kv := range env {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		a = append(a, "-e", k)
		// A path the suite hands out outside the work directory (a
		// companion's manifest): its directory, read-only, same path.
		if filepath.IsAbs(v) && !strings.HasPrefix(v, r.work+"/") {
			if st, err := os.Stat(v); err == nil {
				d := v
				if !st.IsDir() {
					d = filepath.Dir(v)
				}
				if !mounted[d] {
					mounted[d] = true
					a = append(a, "-v", d+":"+d+":ro")
				}
			}
		}
	}
	a = append(a, c.RunArgs...)
	a = append(a, c.Image)
	return append(a, cmd...), cn
}

// ctl runs `<engine> <args...> <container>` and ignores its result (an
// unpause of a running container, or a kill of a gone one, fails harmlessly).
func ctl(container string, args ...string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, containerEngine(), append(args, container)...).Run()
}

// containerSignal maps a host signal onto the container.
func containerSignal(container string, s syscall.Signal) {
	switch s {
	case syscall.SIGSTOP:
		ctl(container, "pause")
	case syscall.SIGCONT:
		ctl(container, "unpause")
	case syscall.SIGKILL:
		ctl(container, "kill")
	default:
		ctl(container, "kill", "--signal", strconv.Itoa(int(s)))
	}
}

// removeContainers removes every container this run started.
func (r *runner) removeContainers() {
	eng := containerEngine()
	out, err := exec.Command(eng, "ps", "-aq", "--filter", "label=heain.conformance="+strconv.Itoa(os.Getpid())).Output()
	if err != nil {
		return
	}
	ids := strings.Fields(string(out))
	if len(ids) == 0 {
		return
	}
	_ = exec.Command(eng, append([]string{"rm", "-f"}, ids...)...).Run()
	r.logf("removed %d container(s) of this run", len(ids))
}
