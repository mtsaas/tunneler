# One image for both server roles:
#   docker run IMAGE start coordinator --config /etc/tunneler/config.json
#   docker run IMAGE start exit --kubernetes
#
# The build stage runs on the build host's own architecture and cross-compiles
# for the target, so a multi-platform build never runs Go under emulation.
FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /tunneler ./cmd/tunneler

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /tunneler /tunneler
ENTRYPOINT ["/tunneler"]
