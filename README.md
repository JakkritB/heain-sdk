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

## Step 3d: peer certificate status (2026-10-05)

- **Revocation:** the app-side server and `App.Call` now check the other app's certificate with core (`GET /v1/app/certs/{serial}`, core 1.3) besides the chain and the app OU. A revoked, expired or out-of-probation certificate is refused (`403 certificate_revoked` on the server; an error on the calling side). Answers are cached for `RevocationTTL` (10 s, as core caches the Master's answer). **Fail closed:** if core cannot answer, the call is refused (`503 revocation_unavailable`).
- Needs heain-core with Step 3d (it reports `core_version` 1.3.0).
- Core's P3 `/execute` (the legacy `/ingest` path) now hands jobs to apps through the App API, so an SDK `Worker` also runs those jobs, with no change in the app.

Live test: `bash scripts/live_3d.sh` (needs `~/heain-core`).

## Step 3e-2: conformance suite (2026-10-06)

An app is done only when it passes the conformance suite (spec 05):

```
go build -o /tmp/heain-conformance ./conformance/cmd/heain-conformance
/tmp/heain-conformance run --app ./conformance/refapp --core ~/heain-core --out ./conformance-report
```

- **What it does:** builds heain-core and the harness from source (static), the app from its own `Dockerfile`, and runs them with Docker Compose. Every image is `FROM scratch`, so nothing is pulled. Phase *single* (one core node) runs C1–C9 and C11–C14; phase *offline* (G ← S1, G ← W through a proxy the driver cuts) runs C10. Exit code 0 = pass; `report.json`, `report.txt` and the containers' logs are written to `--out`.
- **How the app is run — the container contract** (`heain.StartFromEnv`): the app reads `HEAIN_MANIFEST`, `HEAIN_INSTANCE`, `HEAIN_CORE_URL`, `HEAIN_CORE_ID`, `HEAIN_CA`, `HEAIN_STATE_DIR`, `HEAIN_ENDPOINT_BASE`, `HEAIN_LISTEN`, and enrolls through provisioning from `HEAIN_ENROLL_TOKEN` (+ `HEAIN_CHAIN`, `HEAIN_ENROLL_CORE_URL/ID`) when it has no certificate yet. The manifest is validated before enrolment. The app runs in its core's network namespace (C13: job claims only from the node).
- **What the app ships — `conformance.yaml`** beside its manifest: `manifest`, optional `prebuild` (run before `docker build`, with `CGO_ENABLED=0`), `port`, one sample request per endpoint (`method`, `path`, `body`, `expect`, `secret`), one sample job per job capability (`capability`, `payload`, `expect_output`, `delivery`), and optional `p5` / `p7` triggers. See `conformance/refapp/`.
- **Reference app `conformance/refapp`:** formal and non-formal endpoints, an AI endpoint and an AI job with signed records and a model hash, two unlinkable lanes, jobs, P5, P7, an app-to-app call through discovery, offline rules and its own journal events. It passes C1–C14.
- **Found by C10 and fixed in the SDK:** an app learns the node's mode by polling (5 s), so right after a partition it could still serve a capability that is not allowed offline. The server now re-reads the mode from core first when its copy is older than `ModeFreshness` (1 s) — only for capabilities not allowed offline.
- **Known gap reported by the suite:** C9 "data classes never leave their declared scope" is reported as *skip*: core does not filter discovery by zone yet.

## Step 3e-3: the conformance suite without Docker (2026-10-06)

**Author decision (2026-10-06):** Docker was only an example in the design. Developers build and package apps in their own way, so nothing in heain requires Docker — **this replaces the Docker Compose harness of 3e-2.**

```
go build -o /tmp/heain-conformance ./conformance/cmd/heain-conformance
/tmp/heain-conformance run --app ./conformance/refapp --core ~/heain-core --out ./conformance-report
```

- The suite builds heain-core and runs its nodes as **processes on this machine** (ports 28100–28110). The app reaches its core over loopback, as on a real node.
- The app is built and started with **its own commands** in `conformance.yaml`: `build` (optional) and `start` (required, foreground) — a binary, an interpreter, or `docker run ...` if the developer wants. The suite sets the `HEAIN_*` variables (`heain.StartFromEnv` reads them; apps in other languages will read them through heain-agent). Apps that persist outside `HEAIN_STATE_DIR` list those directories in `data_dirs` (C14).
- The app is controlled with signals: SIGTERM (graceful leave), SIGSTOP/SIGCONT (missed heartbeats), and a second start with a broken manifest (C1).
- **C13:** a claim through this machine's LAN address is refused (`locality_violation`); in the offline phase every byte between W and G passes the suite's proxy, which looks for the test data in clear. **C10:** the proxy is cut and healed by the suite.
- No Dockerfile is needed; `conformance/refapp` has none.

## Step 4a: dependency patterns and companion apps (2026-10-06)

- **`uses[]` patterns** (decided 2026-10-06 for orchestrators such as heain-job, which serve modules they cannot list in advance): `app` and each capability may contain `*`, e.g. `{app: "*", capabilities: ["*.split", "*.unit", "*.merge"]}`. `App.Call` and `App.Submit` match against them; the manifest check refuses anything but names and `*`. Conformance C12 uses the same matching.
- **Conformance companions:** `conformance.yaml` may list `companions:` — directories of other apps the app under test needs (each with its own `conformance.yaml`). The suite builds, enrolls and starts them alongside the app (not under test), on the same node.

## Step 4a-2: per-job retries and lease extension (2026-10-06)

Uses two controls added to heain-core in Step 4a-2:
- **`JobRequest.MaxAttempts`** (sent as `max_attempts`): lowers the deployment's `p3.max_retry` for one job; `1` = at most one automatic attempt — if it fails or its lease runs out, the job stops (`retries_exhausted`) and an Approver decides (P5). For exactly-once / transactional work. `0` (default) = the policy value; negative is refused before any call.
- **The Worker extends leases:** while a handler runs, the Worker calls `POST /v1/app/jobs/{ticket}/extend` about every third of the lease, asking for the same length again (core caps it at `dispatch.lease_max`). The handler's ctx ends only when an extension is refused or core cannot be reached before the lease runs out. `ctx.Deadline()` is not moved by extensions. `Worker.FixedLease = true` turns this off.

## Step 4b-1: data keys and node-local data (2026-10-06)

- **`App.DataKey(ctx, name)`** returns a 256-bit data key held by heain-core's KMS (`POST /v1/app/keys`, create-or-get; every instance of the app on the node gets the same key). It is cached in memory only — never write it to disk. **`App.Sealer(ctx, name)`** / **`NewSealer(key)`**: AES-256-GCM, `Seal(plaintext, aad)` → nonce‖ciphertext, `Open(sealed, aad)` (`ErrOpen` for a wrong key, aad or tampered data). **`App.DestroyDataKey(ctx, name)`** crypto-shreds the key in core; data sealed under it can never be opened again, and a later `DataKey(name)` makes a new key. This is how an app meets `encrypted_at_rest: true` for what it persists (spec 00 §3).
- **`Manifest.NodeLocalCapabilities()`** lists the capabilities that handle a `sovereignty: node-local` data class. Core admits their providers only from its own node and never moves their work elsewhere.
- **Conformance:** C9 now checks, for an app with node-local data, that registering its manifest from another host is refused (`locality_violation`); the old "known core gap" skip is gone. Harness fixes: C2 sends the identity checks with the first endpoint's own method (a `PUT`-only endpoint answered 405 before), and C12 no longer counts the app's own `App.Audit` events as calls to itself.
