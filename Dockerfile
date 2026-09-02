# syntax=docker/dockerfile:1.5
# Dockerfile — aocs-compliance-svc
#
# Multi-stage build:
#   builder: compiles the Go binary
#   runtime: minimal distroless image
#
# Ring: 0-adjacent — always-on compliance observability layer.
# Depends on Ring 1 (ocx-core-svc / aocs-hub) at runtime for agent data.

FROM golang:1.23-alpine AS builder

WORKDIR /src

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
# Replace directive points to ocx-shared-go — copy it into the build context
COPY ../ocx-shared-go /shared-go/
RUN sed -i 's|../ocx-shared-go|/shared-go|g' go.mod && go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -ldflags="-w -s" -o /bin/aocs-compliance ./cmd/aocs-compliance

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

LABEL org.opencontainers.image.title="aocs-compliance-svc" \
      org.opencontainers.image.description="AOCS Compliance — ZKP, DLP, cases, evidence vault, SOC2/EU AI Act reports" \
      org.opencontainers.image.source="https://github.com/Generativebots/aocs-compliance-svc"

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /bin/aocs-compliance /aocs-compliance

# Cloud Run injects PORT. Default 8089 (compliance — after billing :8087, marketplace :8088)
ENV PORT=8089
EXPOSE 8089

USER nonroot:nonroot
ENTRYPOINT ["/aocs-compliance"]
