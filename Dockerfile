# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32

FROM golang:1.27.1-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS build
ARG version

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
COPY cmd ./cmd
COPY internal ./internal
RUN go mod download

RUN CGO_ENABLED=0 GO111MODULE=auto go build -ldflags "-X github.com/prometheus/common/version.Version=${version}" -o /grl-exporter cmd/prometheus_exporter/main.go

FROM gcr.io/distroless/base-debian11@sha256:ac69aa622ea5dcbca0803ca877d47d069f51bd4282d5c96977e0390d7d256455

WORKDIR /

COPY --from=build /grl-exporter /grl-exporter

EXPOSE 2112

USER nonroot:nonroot

ENTRYPOINT ["/grl-exporter"]
