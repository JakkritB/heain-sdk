// Command heain-conformance runs the heain conformance suite (spec 05)
// against an app:
//
//	heain-conformance run --app ./path/to/app [--core ~/heain-core] [--out ./conformance-report]
//
// It builds heain-core from source and starts its nodes as processes on
// this machine, builds and starts the app with the commands in the app's
// conformance.yaml -- any language or packaging: a host process, or a
// container image (`container:`, Docker or Podman; Docker is optional) --
// runs groups C1-C14 and writes report.json and report.txt. Exit code 0
// means pass.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/heainframework/heain-sdk/conformance"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "run" {
		usage()
	}
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	home, _ := os.UserHomeDir()
	app := fs.String("app", "", "directory of the app under test (conformance.yaml and the manifest)")
	conf := fs.String("conf", "conformance.yaml", "the conformance file in the app directory (e.g. conformance.docker.yaml)")
	coreDir := fs.String("core", filepath.Join(home, "heain-core"), "heain-core source directory")
	out := fs.String("out", "conformance-report", "where to write report.json, report.txt and the logs")
	phases := fs.String("phases", "single,offline", "phases: single (C1-C9, C11-C14), offline (C10)")
	keep := fs.Bool("keep", false, "keep the work directory")
	_ = fs.Parse(os.Args[2:])
	if *app == "" {
		usage()
	}
	abs := func(p string) string { a, _ := filepath.Abs(p); return a }
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	rep, err := conformance.Run(ctx, conformance.RunOptions{AppDir: abs(*app), ConfFile: *conf, CoreDir: abs(*coreDir), OutDir: abs(*out),
		Phases: strings.Split(*phases, ","), Keep: *keep, Log: os.Stdout})
	if err != nil {
		fmt.Fprintln(os.Stderr, "heain-conformance:", err)
		os.Exit(2)
	}
	fmt.Print("\n" + rep.Text())
	fmt.Printf("report: %s\n", abs(*out))
	if !rep.Passed() {
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: heain-conformance run --app DIR [--conf FILE] [--core DIR] [--out DIR] [--phases single,offline] [--keep]")
	os.Exit(2)
}
