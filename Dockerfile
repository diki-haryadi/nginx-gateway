FROM golang:1.21-alpine AS builder

# Install necessary build tools and dependencies
RUN apk add --no-cache gcc g++ make git

# Set the working directory
WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum* ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN CGO_ENABLED=1 GOOS=linux go build -a -ldflags '-linkmode external -extldflags "-static"' -o service-manager .

# Create the final lightweight image
FROM alpine:3.18

# Install runtime dependencies
RUN apk add --no-cache ca-certificates certbot nginx sqlite docker-cli

# Create required directories
RUN mkdir -p /app/nginx/conf.d /app/nginx/templates

# Set the working directory
WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/service-manager .

# Copy entrypoint script
COPY docker-entrypoint.sh /app/
RUN chmod +x /app/docker-entrypoint.sh

# Expose ports
EXPOSE 8081

# Set entrypoint
ENTRYPOINT ["/app/docker-entrypoint.sh"]