# Digests pinned for supply-chain integrity (refresh when intentionally upgrading bases).
FROM golang:1.26.6-bookworm@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36 AS build
WORKDIR /src
ARG VERSION=1.0.1
ARG GIT_SHA=unknown
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build \
  -ldflags="-s -w -X github.com/Kyaxris-Labs/Noctaxris-AZ/internal/version.Version=${VERSION}" \
  -o /noctaxris-az ./cmd/noctaxris-az
RUN mkdir -p /var/lib/noctaxris-az && chown 65532:65532 /var/lib/noctaxris-az

FROM gcr.io/distroless/static-debian12:nonroot
ARG VERSION=1.0.1
ARG GIT_SHA=unknown
LABEL org.opencontainers.image.title="Noctaxris-AZ" \
  org.opencontainers.image.description="Azure-shaped local security lab emulator" \
  org.opencontainers.image.source="https://github.com/Kyaxris-Labs/Noctaxris-AZ" \
  org.opencontainers.image.version="${VERSION}" \
  org.opencontainers.image.revision="${GIT_SHA}"
USER nonroot:nonroot
COPY --from=build /noctaxris-az /noctaxris-az
COPY --from=build --chown=65532:65532 /var/lib/noctaxris-az /var/lib/noctaxris-az
EXPOSE 4599
ENTRYPOINT ["/noctaxris-az"]
