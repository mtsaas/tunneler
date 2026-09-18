# One image for both server roles:
#   docker run IMAGE start coordinator --config /etc/tunneler/config.json
#   docker run IMAGE start exit --kubernetes
#
# By default the binary is compiled here, cross-compiled for the target so a
# multi-platform build never runs Go under emulation. CI compiles it outside
# Docker, where the Go build cache persists, and passes --build-arg
# SOURCE=prebuilt with the binaries at dist/<os>/<arch>/tunneler.
ARG SOURCE=build

FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /dist/$TARGETOS/$TARGETARCH/tunneler ./cmd/tunneler

FROM scratch AS prebuilt
COPY dist/ /dist/

FROM $SOURCE AS binaries

FROM gcr.io/distroless/static-debian12:nonroot
ARG TARGETOS TARGETARCH
COPY --from=binaries /dist/$TARGETOS/$TARGETARCH/tunneler /tunneler
ENTRYPOINT ["/tunneler"]
