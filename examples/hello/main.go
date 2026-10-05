// Command hello is the smallest heain-sdk app: it enrolls (optional),
// starts with its manifest, waits until it is admitted, and leaves on
// SIGINT/SIGTERM. Used by the SDK's live tests.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/heainframework/heain-sdk/core"
	"github.com/heainframework/heain-sdk/heain"
	"github.com/heainframework/heain-sdk/provision"
)

func main() {
	man := flag.String("manifest", "heain-app.yaml", "manifest file (.yaml/.yml/.json)")
	inst := flag.String("instance", "a1", "instance id")
	coreURL := flag.String("core", "https://127.0.0.1:18000", "core https base")
	coreID := flag.String("core-id", "G", "core node id")
	cert := flag.String("cert", "app.pem", "app certificate (+chain)")
	key := flag.String("key", "app.key", "app key")
	ca := flag.String("ca", "ca.pem", "root CA")
	enroll := flag.String("enroll-token-json", "", "if set: enroll first with this /provision/token response file, writing -cert/-key")
	chain := flag.String("chain", "", "provisioning CA certificate (for -enroll-token-json)")
	appID := flag.String("app-id", "", "app id (for -enroll-token-json)")
	wait := flag.Duration("wait-active", 60*time.Second, "how long to wait for admission")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *enroll != "" {
		tok, err := readToken(*enroll)
		if err != nil {
			fail("enroll", err)
		}
		dir, _ := os.MkdirTemp("", "hello-enroll")
		res, err := provision.Enroll(ctx, provision.Request{CoreURL: *coreURL, CoreNodeID: *coreID, CAFile: *ca, ChainFile: *chain,
			Token: tok.Token, BootstrapCertPEM: tok.BootstrapCertPEM, BootstrapKeyPEM: tok.BootstrapKeyPEM,
			AppID: *appID, InstanceID: *inst, OutDir: dir})
		if err != nil {
			fail("enroll", err)
		}
		mustCopy(res.CertFile, *cert)
		mustCopy(res.KeyFile, *key)
		fmt.Printf("ENROLLED serial=%s\n", res.Serial)
	}
	app, err := heain.Start(ctx, heain.Options{ManifestPath: *man, InstanceID: *inst,
		Core: core.Config{URL: *coreURL, NodeID: *coreID, CertFile: *cert, KeyFile: *key, CAFile: *ca}})
	if err != nil {
		fail("start", err)
	}
	fmt.Printf("REGISTERED status=%s action=%s\n", app.Status(), app.Registration().ActionID)
	wctx, cancel := context.WithTimeout(ctx, *wait)
	err = app.WaitActive(wctx)
	cancel()
	if err != nil {
		fail("wait", err)
	}
	fmt.Println("ACTIVE")
	<-ctx.Done()
	if err := app.Close(context.Background()); err != nil {
		fail("close", err)
	}
	fmt.Println("DEREGISTERED")
}

type token struct {
	Token            string `json:"token"`
	BootstrapCertPEM string `json:"bootstrap_cert_pem"`
	BootstrapKeyPEM  string `json:"bootstrap_key_pem"`
}

func fail(stage string, err error) {
	fmt.Printf("REFUSED stage=%s: %v\n", stage, err)
	os.Exit(2)
}
