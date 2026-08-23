# syntax=docker/dockerfile:1

FROM golang:1.27.0-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS build
ARG version

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
COPY cmd ./cmd
COPY internal ./internal
RUN go mod download

RUN CGO_ENABLED=0 GO111MODULE=auto go build -ldflags "-X github.com/prometheus/common/version.Version=${version}" -o /grl-exporter cmd/prometheus_exporter/main.go

FROM gcr.io/distroless/base-debian11

WORKDIR /

COPY --from=build /grl-exporter /grl-exporter

EXPOSE 2112

USER nonroot:nonroot

ENTRYPOINT ["/grl-exporter"]
