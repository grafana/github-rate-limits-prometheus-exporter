# syntax=docker/dockerfile:1

FROM golang:1.27.1-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build
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
