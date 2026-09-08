# gruff

Issues OpenVPN configs with embedded, short-lived client certificates. It:

- signs a fresh client certificate per download, attributable to the requesting user
- hands out configs that expire with the profile's `max-session`
- pushes routes to clients
- generates the firewall rules the VPN server opens on connect

## Security model

**The portal authenticates nobody.** It trusts the identity headers set by an SSO
reverse proxy, so anything that can reach it can assert its own username and roles.
It binds `127.0.0.1` by default for that reason, and the Helm chart exposes only the
SSO sidecar. Do not put it on a routable address.

Access is denied by default: a profile is reachable only by a user holding one of the
roles it names, and a profile naming no roles is rejected at startup.

The portal will not start without a CA. `-dev-generate-ca` exists for local
development and warns loudly; it mints a new trust anchor on every run, invalidating
everything issued before.

## Requirements

- a reverse proxy that terminates SSO and sets the configured `X-Auth-*` headers
- an OpenVPN server configured to read the generated `client-config-dir` and rules
- a CA keypair to sign client certificates

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

The chart requires `ca.existingSecret` and `openvpn.existingSecret`, and renders the
traffic path Ingress → SSO proxy `:8000` → portal `127.0.0.1:9000`.
