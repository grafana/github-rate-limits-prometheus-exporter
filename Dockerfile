# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e

FROM golang:1.27.3-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS build
ARG version

WORKDIR /app

RUN apk add --no-cache 'ca-certificates>=20261020-r0' \
    && update-ca-certificates

COPY go.mod ./
COPY go.sum ./
COPY cmd ./cmd
COPY internal ./internal
RUN go mod download

RUN CGO_ENABLED=0 GO111MODULE=auto go build -ldflags "-X github.com/prometheus/common/version.Version=${version}" -o /grl-exporter cmd/prometheus_exporter/main.go

# The exporter is statically linked above; retain CA roots without libc or OpenSSL.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:d62067879de890a1def9da0e7766b7d20810a5e5555cef8506b752437d7a3e88

WORKDIR /

COPY --from=build /grl-exporter /grl-exporter

EXPOSE 2112

USER nonroot:nonroot

ENTRYPOINT ["/grl-exporter"]
