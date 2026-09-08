# gruff

Issues OpenVPN configs with embedded, short-lived client certificates. It:

- signs a fresh client certificate per download, attributable to the requesting user
- hands out configs that expire with the profile's `max-session`
- pushes routes to clients
- generates the firewall rules the VPN server opens on connect

## Security model

Gruff authenticates users itself with OpenID Connect (`auth.mode: oidc`), holds the
session in an encrypted cookie, and is meant to be exposed.

It can instead trust identity headers from an SSO proxy in front of it
(`auth.mode: proxy`, the default). In that mode it **authenticates nobody**, so
anything that can reach it can assert its own username and roles — it binds
`127.0.0.1` and must not be put on a routable address.

Access is denied by default: a profile is reachable only by a user holding one of the
roles it names, and a profile naming no roles is rejected at startup.

The portal will not start without a CA. `-dev-generate-ca` exists for local
development and warns loudly; it mints a new trust anchor on every run, invalidating
everything issued before.

## Requirements

- an OpenID Connect provider (or, in proxy mode, a reverse proxy that sets the
  configured `X-Auth-*` headers)
- an OpenVPN server configured to read the generated `client-config-dir` and rules
- a CA keypair to sign client certificates, and an SSH CA key for SSH profiles

## Build and run

```sh
make check          # go vet, gofmt, go test -race
make build
./portal --config configs/conf.yaml
```

For local development, without a CA to hand:

```sh
mkdir -p tmp/tls
./portal --config configs/conf.yaml --dev-generate-ca --dev-ca-dir tmp/tls
```

Flags: `--config`, `--log-level`, `--version`, and the two `-dev-*` flags above.

## Examples

- [Example config](configs/conf.yaml)
- [Helm chart](deployment/helm)

The chart requires `ca.existingSecret`, `openvpn.existingSecret` and
`auth.existingSecret`, and renders the traffic path Ingress → Gruff `:9000`.

`/setup` shows the server-side configuration your hosts need: `TrustedUserCAKeys`
and `AuthorizedPrincipalsFile` for sshd, and the OpenVPN server directives.
