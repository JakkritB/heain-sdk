# heain-sdk

Shared, public HTTP/mTLS client for any [HEAIN](https://heainframework.org)
Layer 3 Application Profile module (`heain-job`, `heain-image`,
`heain-video`, `heain-access`, ...) to talk to a `heain-core` node.

## What this is — and isn't

- **It is** the wire contract (request/response shapes) and a plain
  HTTP/mTLS client for `heain-core`'s existing P1-P4 endpoints
  (`/ingest`, `/dispatch`, `/execute`, `/staging/...`).
- **It is not**, and never will be, a copy of any part of `heain-core`
  itself. `heain-core` is a separate, private repository; this package
  only knows how to *call* it over the network, the same way any
  external client of a public HTTP API would.

Every Layer 3 module repo under [heainframework](https://github.com/heainframework)
imports this package instead of writing its own client, so the client
code is written once and the wire contract stays consistent across every
module.

## Usage

```go
import "github.com/heainframework/heain-sdk/coreclient"

client, err := coreclient.New("https://your-heain-core-node:8443", coreclient.TLSConfig{
    ClientCertFile: "dev-client.crt",
    ClientKeyFile:  "dev-client.key",
    CAFile:         "ca.crt",
    ServerName:     "your-heain-core-node",
})
```

See `coreclient/client.go` for the full method list (`Ingest`, `Dispatch`,
`Execute`, `ConfirmRetrieval`, `RequestErasure`).

## Getting a certificate

Running against a real `heain-core` deployment requires an mTLS client
certificate issued by that deployment's own CA — a runtime trust
relationship, separate from this repository's source code. See
[heainframework.org](https://heainframework.org) for how to get one for
the public sandbox.

## License

Apache License 2.0 — see [LICENSE](./LICENSE).

## heain-sdk v1 (rebuilt 2026-10-05, Step 3)

The old `jobclient` and `coreclient` packages talked to heain-job directly over plain HTTP, without going through heain-core. They are removed; their last state is tagged `legacy-v0`. The `capacity` package (live RAM/GPU probe) stays.

heain-sdk v1 is the universal library an app uses to connect to heain-core through the App API (spec `02-app-api.md`), over mTLS 1.3 with its own app certificate.

| Package | What it does |
|---|---|
| `manifest` | Loads `heain-app.yaml` or `.json` (same schema), with unknown fields refused. Validates the spec 01 §4 rules, the same ones core applies, and checks `app.sdk`. |
| `provision` | Obtains the app certificate through core's provisioning flow: token → CSR → probation → confirm. |
| `core` | The App API client (TLS 1.3, the core's node id verified) and its error type. |
| `heain` | `Start` loads and validates the manifest; **an invalid manifest never starts**. It then checks that the certificate CN is `<app-id>.<instance-id>`, checks the core's API version, registers and keeps the registration alive. `WaitActive` waits for an Approver to admit a new app or version, and `Close` deregisters. |
| `examples/hello` | The smallest app; used by the live tests. |

**Decided 2026-10-05:**
- Manifests may be YAML or JSON.
- `uses[]` is enforced by the SDK (slice 3b).
- Reasoning records are signed over RFC 8785 (JCS) (slice 3b).
- `factors` is required for `role: decision` (slice 3b).

Live test: `bash scripts/live_3a.sh` runs against a real heain-core node and needs `~/heain-core`.
