# Templates and stylesheets are embedded in the binary and Gruff makes no
# outbound TLS calls, so the runtime image needs no filesystem at all: no shell,
# no libc, no CA bundle, nothing to exec if the process is ever subverted.
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

COPY --from=build /gruff /gruff

# Numeric because scratch has no /etc/passwd; matches Kubernetes runAsNonRoot.
USER 65532:65532
EXPOSE 9000

ENTRYPOINT ["/gruff"]
CMD ["--config", "/etc/config/gruff.yml"]
