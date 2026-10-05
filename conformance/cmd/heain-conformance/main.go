// Command heain-conformance runs the heain conformance suite (spec 05)
// against an app:
//
//	heain-conformance run --app ./path/to/app [--core ~/heain-core] [--out ./conformance-report]
//
// It builds heain-core and the harness from source (static, CGO_ENABLED=0),
// the app from its own Dockerfile, starts them with Docker Compose (every
// image FROM scratch: nothing is pulled), runs groups C1-C14 and writes
// report.json and report.txt. Exit code 0 means pass.
//
// The other subcommands run inside the harness containers.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/heainframework/heain-sdk/conformance"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	switch cmd {
	case "run":
		home, _ := os.UserHomeDir()
		app := fs.String("app", "", "directory of the app under test (Dockerfile, conformance.yaml, manifest)")
		coreDir := fs.String("core", filepath.Join(home, "heain-core"), "heain-core source directory")
		sdk := fs.String("sdk", ".", "heain-sdk source directory")
		out := fs.String("out", "conformance-report", "where to write report.json, report.txt and logs")
		phases := fs.String("phases", "single,offline", "phases to run: single (C1-C9, C11-C14), offline (C10)")
		keep := fs.Bool("keep", false, "keep containers and the work directory")
		_ = fs.Parse(args)
		if *app == "" {
			usage()
		}
		abs := func(p string) string { a, _ := filepath.Abs(p); return a }
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		rep, err := conformance.Run(ctx, conformance.RunOptions{AppDir: abs(*app), CoreDir: abs(*coreDir), SDKDir: abs(*sdk), OutDir: abs(*out),
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
	case "pki":
		out := fs.String("out", "/shared", "shared directory")
		nodes := fs.String("nodes", "G=10.77.0.10", "node id=ip list")
		_ = fs.Parse(args)
		if err := conformance.PKI(*out, conformance.ParseNodes(*nodes)); err != nil {
			log.Fatal(err)
		}
	case "hold":
		conformance.Hold()
	case "proxy":
		listen := fs.String("listen", "0.0.0.0:28000", "listen address")
		to := fs.String("to", "", "target host:port")
		state := fs.String("state", "/shared/proxy.state", "state file (\"cut\" cuts)")
		_ = fs.Parse(args)
		conformance.Proxy(*listen, *to, *state)
	case "capture":
		iface := fs.String("iface", "eth0", "interface")
		markers := fs.String("markers", "/shared/markers.txt", "markers file")
		out := fs.String("out", "/shared/capture.json", "result file")
		_ = fs.Parse(args)
		if err := conformance.Capture(*iface, *markers, *out); err != nil {
			log.Fatal(err)
		}
	case "driver":
		phase := fs.String("phase", "single", "single | offline")
		shared := fs.String("shared", "/shared", "shared directory")
		_ = fs.Parse(args)
		log.SetFlags(log.Ltime)
		d, err := conformance.NewDriver(*shared)
		if err != nil {
			log.Fatal(err)
		}
		switch *phase {
		case "single":
			d.RunSingle(context.Background())
		case "offline":
			d.RunOffline(context.Background())
		}
		fmt.Print(d.Rep.Text())
	case "remote-claim":
		shared := fs.String("shared", "/shared", "shared directory")
		coreURL := fs.String("core", "https://10.77.0.10:18000", "core URL (as seen from another host)")
		_ = fs.Parse(args)
		code, body, err := conformance.RemoteClaim(*shared, *coreURL)
		fmt.Printf("remote claim from another host: %d %s %v\n", code, strings.TrimSpace(body), err)
		if code == http.StatusForbidden && strings.Contains(body, "locality_violation") {
			os.Exit(0)
		}
		os.Exit(1)
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: heain-conformance run --app DIR [--core DIR] [--sdk DIR] [--out DIR] [--phases single,offline] [--keep]")
	os.Exit(2)
}
