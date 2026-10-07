package heain

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/heainframework/heain-sdk/core"
	"github.com/heainframework/heain-sdk/manifest"
	"github.com/heainframework/heain-sdk/provision"
)

// The container contract (Step 3e): an app built on heain-sdk can be
// configured entirely from these environment variables, which is how the
// conformance harness (and a deployment) runs it.
//
//	HEAIN_MANIFEST            manifest file (default /app/heain-app.yaml)
//	HEAIN_INSTANCE            instance id (required)
//	HEAIN_CORE_URL            https base of the core on this node (default https://127.0.0.1:18000)
//	HEAIN_CORE_ID             that core's node id (required)
//	HEAIN_CA                  deployment root CA (required)
//	HEAIN_CERT, HEAIN_KEY     app certificate and key (default <state>/app.pem, <state>/app.key)
//	HEAIN_STATE_DIR           the app's durable SDK state (default /state)
//	HEAIN_ENDPOINT_BASE       https base other apps reach this instance at (direct capabilities)
//	HEAIN_LISTEN              address the app serves its endpoints on (read by the app, see Listen)
//	HEAIN_ENROLL_TOKEN        if the certificate does not exist yet: a /provision/token answer
//	                          (JSON file); the SDK waits for it (HEAIN_ENROLL_WAIT, default 120 s)
//	                          and enrolls through provisioning
//	HEAIN_CHAIN               provisioning CA certificate (for enrolment)
//	HEAIN_ENROLL_CORE_URL, HEAIN_ENROLL_CORE_ID  core that issued the token (default the core above)
const (
	EnvManifest = "HEAIN_MANIFEST"
	EnvListen   = "HEAIN_LISTEN"
)

// Listen is HEAIN_LISTEN, or def.
func Listen(def string) string {
	if v := os.Getenv(EnvListen); v != "" {
		return v
	}
	return def
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// StartFromEnv validates the manifest (an invalid one never starts and
// never reaches core, also before enrolment), enrolls if the app has no
// certificate yet, and starts the app.
func StartFromEnv(ctx context.Context) (*App, error) {
	state := getenv("HEAIN_STATE_DIR", "/state")
	o := Options{
		ManifestPath: getenv(EnvManifest, "/app/heain-app.yaml"),
		InstanceID:   os.Getenv("HEAIN_INSTANCE"),
		EndpointBase: os.Getenv("HEAIN_ENDPOINT_BASE"),
		StateDir:     state,
		Core: core.Config{URL: getenv("HEAIN_CORE_URL", "https://127.0.0.1:18000"), NodeID: os.Getenv("HEAIN_CORE_ID"),
			CertFile: getenv("HEAIN_CERT", filepath.Join(state, "app.pem")), KeyFile: getenv("HEAIN_KEY", filepath.Join(state, "app.key")),
			CAFile: os.Getenv("HEAIN_CA")},
	}
	m, err := manifest.Load(o.ManifestPath)
	if err != nil {
		return nil, err
	}
	if err := manifest.Validate(m); err != nil {
		return nil, err
	}
	if err := checkSDK(m); err != nil {
		return nil, err
	}
	if o.InstanceID == "" || o.Core.NodeID == "" || o.Core.CAFile == "" {
		return nil, fmt.Errorf("heain-sdk: HEAIN_INSTANCE, HEAIN_CORE_ID and HEAIN_CA are required")
	}
	if _, err := os.Stat(o.Core.CertFile); os.IsNotExist(err) {
		if err := enrollFromEnv(ctx, m.App.ID, o); err != nil {
			return nil, err
		}
	}
	return Start(ctx, o)
}

func enrollFromEnv(ctx context.Context, appID string, o Options) error {
	tokFile := os.Getenv("HEAIN_ENROLL_TOKEN")
	if tokFile == "" {
		return fmt.Errorf("heain-sdk: no certificate at %s and no HEAIN_ENROLL_TOKEN", o.Core.CertFile)
	}
	wait, err := time.ParseDuration(getenv("HEAIN_ENROLL_WAIT", "120s"))
	if err != nil {
		return fmt.Errorf("heain-sdk: HEAIN_ENROLL_WAIT: %w", err)
	}
	var raw []byte
	deadline := time.Now().Add(wait)
	for {
		if raw, err = os.ReadFile(tokFile); err == nil && len(strings.TrimSpace(string(raw))) > 0 {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("heain-sdk: enrolment token %s did not appear within %v", tokFile, wait)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	var tok struct {
		Token            string `json:"token"`
		BootstrapCertPEM string `json:"bootstrap_cert_pem"`
		BootstrapKeyPEM  string `json:"bootstrap_key_pem"`
	}
	if err := json.Unmarshal(raw, &tok); err != nil {
		return fmt.Errorf("heain-sdk: enrolment token: %w", err)
	}
	dir := filepath.Dir(o.Core.CertFile)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	res, err := provision.Enroll(ctx, provision.Request{CoreURL: getenv("HEAIN_ENROLL_CORE_URL", o.Core.URL), CoreNodeID: getenv("HEAIN_ENROLL_CORE_ID", o.Core.NodeID),
		CAFile: o.Core.CAFile, ChainFile: os.Getenv("HEAIN_CHAIN"), Token: tok.Token, BootstrapCertPEM: tok.BootstrapCertPEM,
		BootstrapKeyPEM: tok.BootstrapKeyPEM, AppID: appID, InstanceID: o.InstanceID, OutDir: dir})
	if err != nil {
		return err
	}
	for from, to := range map[string]string{res.CertFile: o.Core.CertFile, res.KeyFile: o.Core.KeyFile} {
		if from != to {
			b, err := os.ReadFile(from)
			if err == nil {
				err = os.WriteFile(to, b, 0o600)
			}
			if err != nil {
				return err
			}
		}
	}
	return nil
}
