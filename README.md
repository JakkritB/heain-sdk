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

## Step 3b: serving, calling, reasoning records (2026-10-05)

| API (package `heain`) | What it does |
|---|---|
| `App.NewServer`, `Server.Handle` / `HandleFunc`, `Serve`, `ListenAndServe` | Serves the app's `execution: direct` endpoints over mTLS 1.3. Callers must present an app certificate (OU `heain-sdk-client`). Only endpoints declared in the manifest can be handled, and `Serve` refuses to start until every declared endpoint has a handler. |
| (automatic) formal audit | Every call to a `formal: true` endpoint produces **exactly one** audit event in core (`app.event`): outcome `ok`, `error:<status>` or `refused:...`, with the caller, method, path, status and the ids of its reasoning records. Non-formal endpoints produce none. If core cannot record the event, the answer is withheld (`503 audit_unavailable`). |
| (automatic) lanes | A capability with a `lane` requires `X-Heain-Lane` to match. A trace id seen in one lane of a `lanes.unlinkable` pair is refused in the other (`lane_violation`), and the refused id is not written into that lane's audit. |
| `App.Reason(ctx, Decision)` | Writes an AI reasoning record (spec 04) to core: the input as SHA-256 only (raw input never leaves the app), model from the manifest, `factors` required for `role: decision`, signed over RFC 8785 (JCS) with the app key. `VerifyRecord` checks a signature. An `ai.used` capability whose record is required that answers without one is refused (`500 reasoning_record_missing`). |
| `App.Discover`, `App.Call(ctx, CallSpec)` | Calls another app: only a dependency declared in `uses[]` (checked before any network call, `ErrNotDeclared`), resolved through core discovery (cached 10 s, round robin), over mTLS with the callee's certificate checked to be exactly `<app-id>.<instance-id>` of the discovered instance. The trace id is carried on, except into a different lane, where a fresh one is started. |
| `TraceID`, `Lane`, `Caller`, `WithTrace` | The request's trace, lane and calling app instance. |
| `examples/greeter`, `examples/greeter-caller` | A server with formal and non-formal endpoints, an AI capability and two unlinkable lanes, and an app that calls it. |

Live test: `bash scripts/live_3b.sh` (needs `~/heain-core`).

Known limit: the app-side server checks that the caller's certificate chains to the deployment CA and is an app certificate, but not core's revocation list; core's own endpoints do check it.

## Step 3c: jobs, P5, P7, offline mode and journal (2026-10-05)

| API (package `heain`) | What it does |
|---|---|
| `App.Submit(ctx, JobRequest)` | Submits a job for an `execution: job` capability (P1). The capability must be declared in `uses[]` (checked before any call). A transient failure is retried with the same `Idempotency-Key`, so the job is queued at most once. |
| `App.Job`, `App.WaitJob`, `App.ConfirmRetrieval`, `App.RequestErasure` | Status and output (submitter only); P4 disposal and erasure. |
| `App.NewWorker`, `Worker.Handle(capability, handler)`, `Worker.Run` | The pull model: claims jobs from the core on the app's own node (long poll), runs the handler under the lease (ctx ends with it; the payload is zeroed afterwards), then completes or fails. `Permanent(err)` = not retryable; any other error is retried by core (`p3.max_retry`, then the Approver). For a formal capability **each attempt is audited once**; if the event cannot be written the attempt fails (retryable) instead of delivering. An AI capability that requires a record and has none fails with `reasoning_record_missing`. A handler panic fails the attempt (retryable). |
| `App.Propose`, `App.PolicyStatus`, `App.WaitPolicy` | P5 for app-defined actions: `AUTO_APPROVED`, `WAITING_APPROVAL` → `APPROVED` / `DENIED`. Thresholds are policy, never set by the app. |
| `App.Broadcast` | P7 discovery, always through P5 (`KNOWLEDGE_UPDATE`); core sanitizes an approved payload. |
| `App.FetchMode`, `App.CurrentMode`, `App.OnModeChange`, `App.AllowedNow` | The node's mode (`normal` / `standalone`, polled every 5 s by default) and a callback on change. While standalone, `AllowedNow` follows core: the manifest's `offline.allowed` (absent = all) minus the admin's `offline.policy` deny list. The server refuses other capabilities (`409 standalone_not_allowed`, audited) and the Worker does not claim them. |
| `App.Journal(ctx, kind, lane, data)`, `App.JournalProgress` | The app's own domain events in the node's offline journal. `app_seq` comes from a durable counter in `Options.StateDir` (default: the key file's directory), reserved before sending: a retry reuses its number, a restart never does. Formal calls need no journal call: core journals their audit events while standalone. |
| `examples/worker`, `examples/ops` | A job worker (text.upper allowed offline, text.tone with AI records) and a command-line app for jobs, P5, P7, mode and journal. |

Live test: `bash scripts/live_3c.sh` (needs `~/heain-core`, ~6 min).

Known limit (core, by design): on a Worker node an app certificate is checked with the Master; cut off, the node falls back to its escrowed copy of the Master's state (`escrow.sync_interval`, default 10 s). An app enrolled less than that before a partition cannot work on the island.
