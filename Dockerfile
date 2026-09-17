# One image for both server roles:
#   docker run IMAGE start coordinator --config /etc/tunneler/config.json
#   docker run IMAGE start exit --cluster=prod
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /tunneler ./cmd/tunneler

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /tunneler /tunneler
ENTRYPOINT ["/tunneler"]
