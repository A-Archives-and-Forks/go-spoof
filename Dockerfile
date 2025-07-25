# Stage 1: Build the GoSpoof binary
FROM golang:1.22 as builder

# Set working dir and copy everything
WORKDIR /app
COPY . .

# Build the binary from cmd/gospoof
RUN cd cmd/gospoof && go build -o /gospoof

# Stage 2: Run with a minimal image
FROM debian:bullseye-slim

# Copy the compiled binary
COPY --from=builder /gospoof /usr/bin/gospoof

# Optional: expose a port if your server uses one
# EXPOSE 8080

ENTRYPOINT ["gospoof"]