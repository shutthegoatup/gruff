# Templates and stylesheets are embedded in the binary, so the runtime image is
# a static binary and a trust store: no shell, no libc, nothing to exec if the
# process is ever subverted.
FROM golang:1.27 AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG GIT_COMMIT=unknown
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${GIT_COMMIT}" \
      -o /gruff ./cmd/gruff

# Fail the build rather than ship a binary that would need a dynamic loader
# scratch cannot provide.
RUN ! ldd /gruff 2>/dev/null | grep -q . || (echo "binary is not static" >&2; exit 1)

FROM scratch

# In OIDC mode Gruff calls the provider's discovery, token and JWKS endpoints
# over HTTPS. A CGO-free binary reads its roots from disk, so on a bare scratch
# image every one of those calls fails to verify and sign-in cannot work.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

COPY --from=build /gruff /gruff

# Numeric because scratch has no /etc/passwd; matches Kubernetes runAsNonRoot.
USER 65532:65532
EXPOSE 9000

ENTRYPOINT ["/gruff"]
CMD ["--config", "/etc/config/gruff.yml"]
