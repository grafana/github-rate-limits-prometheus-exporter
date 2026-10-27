# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e

FROM golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build
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
FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99

WORKDIR /

COPY --from=build /grl-exporter /grl-exporter

EXPOSE 2112

USER nonroot:nonroot

ENTRYPOINT ["/grl-exporter"]
