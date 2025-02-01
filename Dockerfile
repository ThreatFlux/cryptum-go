# syntax=docker/dockerfile:1.4
# Build stage
FROM threatflux/go-builder:latest AS builder

# Build arguments for version information
ARG VERSION
ARG BUILD_DATE
ARG GIT_COMMIT

WORKDIR /build

# Verify go mod integrity first
COPY go.mod ./
RUN go mod verify

# Copy source code
COPY . .

# Run security scan
RUN go install golang.org/x/vuln/cmd/govulncheck@latest
RUN govulncheck ./...

# Build the binary with additional security flags
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -buildvcs=false -trimpath \
    -ldflags="-w -s \
    -X main.Version=${VERSION} \
    -X main.BuildDate=${BUILD_DATE} \
    -X main.GitCommit=${GIT_COMMIT}" \
    -o cryptum ./cmd/cryptum

# Verify binary
RUN ./cryptum --version || true

# Final stage - using specific Alpine version for security
FROM alpine:3.21.2 AS final

# Build arguments for labels
ARG VERSION
ARG BUILD_DATE
ARG GIT_COMMIT

# Add labels according to OCI image spec
LABEL org.opencontainers.image.title="Cryptum" \
      org.opencontainers.image.description="Cryptum secure container image" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${GIT_COMMIT}" \
      org.opencontainers.image.vendor="ThreatFlux" \
      org.opencontainers.image.url="https://github.com/threatflux/cryptum" \
      org.opencontainers.image.documentation="https://github.com/threatflux/cryptum/docs"

# Add non-root user
RUN addgroup -g 10001 -S cryptum && \
    adduser -u 10001 -S cryptum -G cryptum

# Install minimum required packages
RUN apk --no-cache add \
    ca-certificates \
    tzdata && \
    # Ensure certificates are up to date
    update-ca-certificates

# Create and set permissions for application directories
RUN mkdir -p /data && \
    chown -R cryptum:cryptum /data && \
    chmod 755 /data

# Copy the binary from builder (in final stage)
COPY --from=builder --chown=cryptum:cryptum /build/cryptum /usr/local/bin/cryptum

# Set working directory
WORKDIR /data

# Switch to non-root user
USER cryptum:cryptum

# Document volumes
VOLUME ["/data"]

# Expose health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD cryptum health || exit 1

# Define security options
# These should be set at runtime, but documenting here
# docker run --security-opt=no-new-privileges \
#           --cap-drop=ALL \
#           --security-opt seccomp=default.json \
#           --read-only \
#           image-name

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/cryptum"]

# Default command shows help
CMD ["--help"]