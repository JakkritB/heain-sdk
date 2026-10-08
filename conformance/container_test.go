package conformance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestContainerArgs(t *testing.T) {
	work := t.TempDir()
	other := t.TempDir()
	man := filepath.Join(other, "heain-app.yaml")
	if err := os.WriteFile(man, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &runner{work: work}
	c := &Container{Image: "example/app:test", RunArgs: []string{"--gpus", "all"}}
	env := []string{"HEAIN_STATE_DIR=" + filepath.Join(work, "s"), "HEAIN_MANIFEST=" + man, "HEAIN_CORE_URL=https://127.0.0.1:1"}
	args, name := r.containerArgs("app broken/1", c, env, []string{"./run", "x"})
	got := strings.Join(args, " ")
	for _, want := range []string{
		"run --rm --init --name " + name,
		"--network host",
		"-v " + work + ":" + work,
		"-v " + other + ":" + other + ":ro",
		"-e HEAIN_STATE_DIR -e HEAIN_MANIFEST",
		"-e HEAIN_CORE_URL --gpus all example/app:test ./run x",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
	if strings.Contains(got, "https://") || strings.Contains(got, "=") && strings.Contains(got, "HEAIN_STATE_DIR=") {
		t.Errorf("values must be passed by name only: %q", got)
	}
	if strings.ContainsAny(name, " /") {
		t.Errorf("container name %q not sanitized", name)
	}
}

func TestLoadConfContainer(t *testing.T) {
	d := t.TempDir()
	write := func(s string) {
		if err := os.WriteFile(filepath.Join(d, "c.yaml"), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("manifest: heain-app.yaml\ncontainer: {image: a/b:1, dockerfile: Dockerfile}\n")
	c, err := LoadConfFile(d, "c.yaml")
	if err != nil || c.Container == nil || c.Container.Image != "a/b:1" || len(c.Start) != 0 {
		t.Fatalf("container without start: %+v %v", c, err)
	}
	write("manifest: heain-app.yaml\ncontainer: {dockerfile: Dockerfile}\n")
	if _, err := LoadConfFile(d, "c.yaml"); err == nil {
		t.Fatal("a container without image must be refused")
	}
	write("manifest: heain-app.yaml\n")
	if _, err := LoadConfFile(d, "c.yaml"); err == nil {
		t.Fatal("neither start nor container must be refused")
	}
}
