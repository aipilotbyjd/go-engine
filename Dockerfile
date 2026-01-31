# Build stage
FROM golang:1.23-alpine AS builder

ARG SERVICE=frontend
ARG VERSION=dev

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum* ./
RUN go mod download

# Copy source code
COPY . .

# Build the service
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags "-X main.version=${VERSION} -s -w" \
    -o /app/bin/service \
    ./cmd/${SERVICE}

# Runtime stage
FROM alpine:3.19

ARG SERVICE=frontend

RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 linkflow && \
    adduser -u 1000 -G linkflow -s /bin/sh -D linkflow

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/bin/service /app/service

# Copy configs if needed
COPY --from=builder /app/configs /app/configs

# Set ownership
RUN chown -R linkflow:linkflow /app

USER linkflow

EXPOSE 8080 9090

ENTRYPOINT ["/app/service"]
