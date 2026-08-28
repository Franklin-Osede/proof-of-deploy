# Build the manager binary
FROM golang:1.22 AS builder
ARG TARGETOS
ARG TARGETARCH
# Build identity. Defaults match an un-stamped `docker build .` so the image
# never claims a version it was not given.
ARG VERSION=dev
ARG COMMIT=
ARG DATE=

WORKDIR /workspace
# Cache deps before copying source so they are not re-downloaded on code changes.
COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download

# Copy source
COPY cmd/ cmd/
COPY internal/ internal/

# Build a static manager binary. CLI (cmd/verify) is intentionally not shipped
# in the operator image; it is an operator/developer tool, not a runtime component.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -a -trimpath \
      -ldflags "-s -w \
        -X github.com/franklin1014/proof-of-deploy/internal/buildinfo.Version=${VERSION} \
        -X github.com/franklin1014/proof-of-deploy/internal/buildinfo.Commit=${COMMIT} \
        -X github.com/franklin1014/proof-of-deploy/internal/buildinfo.Date=${DATE}" \
      -o manager ./cmd

# Use distroless as minimal base image to package the manager binary.
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/manager .
USER 65532:65532

ENTRYPOINT ["/manager"]
