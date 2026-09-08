# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```sh
make check          # go vet + gofmt check + go test -race ./...  (what CI runs)
make test           # go test -race ./...
make build          # -> ./gruff
make vulncheck      # govulncheck
go test -race ./internal/portal -run TestIssueDenies   # single test
```

Run the binary from anywhere — templates and CSS are embedded, so there is no
working-directory dependency:

```sh
./gruff --config configs/conf.yaml --dev-generate-ca --dev-ca-dir tmp/tls
```

### Exclusive resources

Starting the portal binds `listen` (default `127.0.0.1:9000`) and, with
`configdir-enabled`, writes into `configdir-path`. Both are machine-wide rather than
worktree-scoped — check nothing else is using them before starting, and say when you have.

## Security model

This is the thing to understand before changing anything.

**Two authentication modes, set by `auth.mode`.** Everything downstream works from
a resolved `identity` and does not care which produced it.

- `oidc` — Gruff runs the OpenID Connect code flow itself and owns the session.
  It is meant to be exposed. This is what the Helm chart deploys, and the only
  mode where logging out is possible.
- `proxy` (default) — Gruff **authenticates nobody**, reading identity from the
  `X-Auth-*` headers an upstream SSO proxy is trusted to set. Anything that can
  reach the listener can assert its own roles, so `listen` defaults to loopback
  and it must never be directly exposed.

`p.oidc == nil` is what every "which mode am I in" check keys off.

The OIDC flow keeps no server-side state: CSRF state, PKCE verifier and nonce all
travel in a short-lived encrypted cookie, so a login begun on one replica finishes
on another. Sessions are AES-GCM cookies, expiry enforced from the authenticated
payload rather than the cookie attribute a client controls; rotating the session
key signs everyone out.

Cookie names drop the `__Host-` prefix when `insecure-cookies` is set, because
that prefix *requires* `Secure` — keeping it would emit a cookie every browser
refuses to store, and local development would silently never log in.

Two invariants the tests pin deliberately, because earlier versions broke them:

- **Deny by default.** `config.Profile.AllowedFor` is the only authorization
  decision; it is a pure function over the caller's roles and mutates nothing.
  A profile naming no roles matches nobody and is rejected at startup.
- **No key retention.** `portal.SessionStore` records issuance metadata only. An
  issued private key exists for the life of the response that carries it and is
  never stored, logged or re-rendered.

Unknown and forbidden profiles return identical responses so the portal does not
disclose which profiles exist. `/issued` is scoped to the requesting user, unless
they hold one of `admin-roles` - which grants visibility and revocation over every
session, and no profiles. With `admin-roles` unset nobody is an administrator.

A control that cannot work is not shown: log out appears only when Gruff owns the
session (oidc) or an operator configured a URL that genuinely ends one (proxy).

## Architecture

```
cmd/gruff           flags, wiring, graceful shutdown
internal/config     schema, parsing, strict startup validation
internal/authsession  encrypted stateless session cookies
internal/oidcauth     OpenID Connect code flow with PKCE
internal/pki        X.509 CA loading and VPN certificate issuance
internal/sshca      SSH CA loading and SSH certificate issuance
internal/portal     handlers, routing, middleware, session store, setup page
internal/openvpn    client-config-dir routes and iptables rule generation
web                 templates + CSS + fonts, embedded via //go:embed
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

## Two credential types

VPN and SSH grants are independent: `profiles` and `ssh-profiles` are separate
config blocks with separate roles, so holding a network does not imply login on its
hosts. Both go through the same deny-by-default `AllowedFor`, and both issue
ephemeral credentials Gruff does not retain.

SSH certificates carry `user@profile` as the key ID, so sshd logs the person rather
than an anonymous key, and principals come from config rather than the username.
The bundle ships as a tarball because that is the only delivery that carries the
0600 the private key needs through to disk.

`/setup` renders the server-side configuration an operator needs - `TrustedUserCAKeys`,
`AuthorizedPrincipalsFile`, the OpenVPN server directives - so a deployment outside
the bundled Helm chart has everything it needs. It publishes public material only;
a test asserts no private key can appear there.

## Dependencies

`go.yaml.in/yaml/v3`, `golang.org/x/crypto` (SSH), and `go-oidc`/`x/oauth2` for
the OIDC flow. Token verification and JWKS handling are deliberately not
hand-rolled. Routing is `net/http.ServeMux` patterns,
CSRF is `http.CrossOriginProtection`, logging is `log/slog`. Prefer the standard
library over adding a dependency here, and keep the CSS self-hosted — the strict
`default-src 'none'` CSP depends on there being no external origins.

## Deployment

`deployment/helm/gruff` runs Gruff and OpenVPN in one pod. There is no SSO
sidecar: Gruff authenticates its own callers, and the Ingress targets it directly.
It fails rendering without `ca.existingSecret`, `openvpn.existingSecret` and
`auth.existingSecret`. The
whole portal config, including the `.ovpn` template, is inline in `values.yaml` under
`config:`; Go template braces there need escaping as `{{ "{{ .Session.X }}" }}` so
Helm passes them through.
