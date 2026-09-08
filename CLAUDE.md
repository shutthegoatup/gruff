# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```sh
make check          # go vet + gofmt check + go test -race ./...  (what CI runs)
make test           # go test -race ./...
make build          # -> ./portal
make vulncheck      # govulncheck
go test -race ./internal/portal -run TestIssueDenies   # single test
```

Run the binary from anywhere — templates and CSS are embedded, so there is no
working-directory dependency:

```sh
./portal --config configs/conf.yaml --dev-generate-ca --dev-ca-dir tmp/tls
```

### Exclusive resources

Starting the portal binds `listen` (default `127.0.0.1:9000`) and, with
`configdir-enabled`, writes into `configdir-path`. Both are machine-wide rather than
worktree-scoped — check nothing else is using them before starting, and say when you have.

## Security model

This is the thing to understand before changing anything.

**The portal authenticates nobody.** It reads the caller's identity from the
`X-Auth-*` headers named in config, which an upstream SSO proxy is trusted to set.
Anything that can reach the listener directly can assert its own roles, so `listen`
defaults to loopback and the Helm chart exposes only the SSO sidecar — no Service
targets the portal's port. Preserve both properties.

Two invariants the tests pin deliberately, because earlier versions broke them:

- **Deny by default.** `config.Profile.AllowedFor` is the only authorization
  decision; it is a pure function over the caller's roles and mutates nothing.
  A profile naming no roles matches nobody and is rejected at startup.
- **No key retention.** `portal.SessionStore` records issuance metadata only. An
  issued private key exists for the life of the response that carries it and is
  never stored, logged or re-rendered.

Unknown and forbidden profiles return identical responses so the portal does not
disclose which profiles exist. `/issued` is scoped to the requesting user.

## Architecture

```
cmd/gruff      flags, wiring, graceful shutdown
internal/config     schema, parsing, strict startup validation
internal/pki        CA loading and client certificate issuance
internal/portal     handlers, routing, middleware, session store
internal/openvpn    client-config-dir routes and iptables rule generation
web                 templates + CSS, embedded via //go:embed
```

`portal.Portal` holds config, CA, logger and sessions as fields; handlers are methods.
There is no package-level mutable state anywhere, which is what makes concurrent
requests safe and the packages testable.

**Validation is front-loaded.** `config.Load` rejects bad durations, non-enum protocols
and actions, and profile names outside `^[a-zA-Z0-9_-]+$` — a name reaches both a file
path and a certificate subject. Handlers can therefore assume their inputs are sane,
and a misconfiguration fails the process rather than a request.

**Every network is a CIDR.** `config.Network` (a `netip.Prefix`) is the single
representation for routes and rule destinations alike, and it rejects host bits
(`192.168.1.5/24`) rather than silently masking them. OpenVPN's dotted-quad
`push "route <addr> <mask>"` form is derived in `internal/openvpn` via
`Network.Addr()`/`Network.Netmask()` — never configured separately. Don't reintroduce
a second way to write an address.

**The portal↔OpenVPN coupling** is `internal/openvpn.Write`, which emits per-profile
route files and iptables scripts into `configdir-path`. The OpenVPN container mounts
that same directory as its `client-config-dir`. That shared directory is the only
integration point between the two.

The `.ovpn` body is rendered with `text/template` (it is not HTML) from an
operator-supplied template parsed at startup; the web pages use `html/template`,
parsed once into one template set per page since each defines its own `body`.

## Dependencies

One, deliberately: `go.yaml.in/yaml/v3`. Routing is `net/http.ServeMux` patterns,
CSRF is `http.CrossOriginProtection`, logging is `log/slog`. Prefer the standard
library over adding a dependency here, and keep the CSS self-hosted — the strict
`default-src 'none'` CSP depends on there being no external origins.

## Deployment

`deployment/helm/gruff` runs oauth2-proxy, the portal and OpenVPN in one pod.
It fails rendering without `ca.existingSecret` and `openvpn.existingSecret`. The
whole portal config, including the `.ovpn` template, is inline in `values.yaml` under
`config:`; Go template braces there need escaping as `{{ "{{ .Session.X }}" }}` so
Helm passes them through.
