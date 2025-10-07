# Build stage
FROM golang:1.25.1-alpine AS builder

# Install git and ca-certificates (needed to get dependencies)
RUN apk add --no-cache git ca-certificates

# Set the working directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application with security enhancements
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags="-w -s" -o oauth-service ./cmd/server

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS requests and wget for health checks
RUN apk --no-cache add ca-certificates wget

# Create a non-root user
RUN addgroup -g 1001 appgroup && adduser -u 1001 -G appgroup -s /bin/sh -D appuser

# Create app directory
WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/oauth-service .

# Copy templates directory
COPY --from=builder /app/templates ./templates

# Change ownership to non-root user
RUN chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Expose port 8080 (default port for the OAuth service)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://localhost:8080/test || exit 1

# Command to run the executable
CMD ["./oauth-service"]