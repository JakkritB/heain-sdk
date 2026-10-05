// Package cli holds the flags and start-up steps shared by the example apps:
// optional enrollment through provisioning, then heain.Start.
package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/heainframework/heain-sdk/core"
	"github.com/heainframework/heain-sdk/heain"
	"github.com/heainframework/heain-sdk/provision"
)

// Flags are the common example flags.
type Flags struct {
	Manifest, Instance, Core, CoreID, Cert, Key, CA, Enroll, Chain, AppID *string
	EnrollCore, EnrollCoreID                                              *string
}

// Register adds the common flags to the default flag set.
func Register(defManifest string) *Flags {
	return &Flags{
		Manifest:     flag.String("manifest", defManifest, "manifest file (.yaml/.yml/.json)"),
		Instance:     flag.String("instance", "a1", "instance id"),
		Core:         flag.String("core", "https://127.0.0.1:18000", "core https base"),
		CoreID:       flag.String("core-id", "G", "core node id"),
		Cert:         flag.String("cert", "app.pem", "app certificate (+chain)"),
		Key:          flag.String("key", "app.key", "app key"),
		CA:           flag.String("ca", "ca.pem", "root CA"),
		Enroll:       flag.String("enroll-token-json", "", "if set: enroll first with this /provision/token response file, writing -cert/-key"),
		Chain:        flag.String("chain", "", "provisioning CA certificate (for -enroll-token-json)"),
		AppID:        flag.String("app-id", "", "app id (for -enroll-token-json)"),
		EnrollCore:   flag.String("enroll-core", "", "core that issued the token (default -core)"),
		EnrollCoreID: flag.String("enroll-core-id", "", "its node id (default -core-id)"),
	}
}

// Start enrolls (if asked) and starts the app.
func (f *Flags) Start(ctx context.Context, endpointBase string) *heain.App {
	if *f.Enroll != "" {
		var tok struct {
			Token            string `json:"token"`
			BootstrapCertPEM string `json:"bootstrap_cert_pem"`
			BootstrapKeyPEM  string `json:"bootstrap_key_pem"`
		}
		raw, err := os.ReadFile(*f.Enroll)
		if err == nil {
			err = json.Unmarshal(raw, &tok)
		}
		if err != nil {
			Fail("enroll", err)
		}
		dir, _ := os.MkdirTemp("", "heain-enroll")
		eu, eid := *f.Core, *f.CoreID
		if *f.EnrollCore != "" {
			eu, eid = *f.EnrollCore, *f.EnrollCoreID
		}
		res, err := provision.Enroll(ctx, provision.Request{CoreURL: eu, CoreNodeID: eid, CAFile: *f.CA, ChainFile: *f.Chain,
			Token: tok.Token, BootstrapCertPEM: tok.BootstrapCertPEM, BootstrapKeyPEM: tok.BootstrapKeyPEM,
			AppID: *f.AppID, InstanceID: *f.Instance, OutDir: dir})
		if err != nil {
			Fail("enroll", err)
		}
		copyFile(res.CertFile, *f.Cert)
		copyFile(res.KeyFile, *f.Key)
		fmt.Printf("ENROLLED serial=%s\n", res.Serial)
	}
	app, err := heain.Start(ctx, heain.Options{ManifestPath: *f.Manifest, InstanceID: *f.Instance, EndpointBase: endpointBase,
		Core: core.Config{URL: *f.Core, NodeID: *f.CoreID, CertFile: *f.Cert, KeyFile: *f.Key, CAFile: *f.CA}})
	if err != nil {
		Fail("start", err)
	}
	fmt.Printf("REGISTERED status=%s action=%s\n", app.Status(), app.Registration().ActionID)
	return app
}

// Fail prints a REFUSED line and exits 2.
func Fail(stage string, err error) {
	fmt.Printf("REFUSED stage=%s: %v\n", stage, err)
	os.Exit(2)
}

func copyFile(from, to string) {
	raw, err := os.ReadFile(from)
	if err == nil {
		err = os.WriteFile(to, raw, 0o600)
	}
	if err != nil {
		Fail("copy", err)
	}
}
