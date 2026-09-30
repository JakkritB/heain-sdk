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
