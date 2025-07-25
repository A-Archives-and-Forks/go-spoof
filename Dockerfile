# Build stage
FROM golang:1.22 as builder
WORKDIR /app
COPY . .
RUN cd cmd/gospoof && CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /gospoof

# Runtime stage
FROM debian:bullseye-slim
ENV DEBIAN_FRONTEND=noninteractive

# Copy binary and required files
COPY --from=builder /gospoof /usr/bin/gospoof
COPY tools /tools

ENTRYPOINT ["gospoof"]
# Build GoSpoof binary
FROM golang:1.22 as builder

WORKDIR /app
COPY . .
RUN cd cmd/gospoof && CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /gospoof

# Runtime with Node & WebUI
FROM debian:bullseye-slim

ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies: Node.js, npm, and system libs
RUN apt update && \
    apt install -y curl gnupg ca-certificates build-essential sqlite3 && \
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt install -y nodejs

# Copy Go binary and tools
COPY --from=builder /gospoof /usr/bin/gospoof
COPY tools /tools
COPY Web /Web

# Install WebUI dependencies
RUN cd /Web/Server && npm install express ejs express-ejs-layouts socket.io bcrypt better-sqlite3 express-rate-limit express-session validator multer

# Expose WebUI port
EXPOSE 3000

ENTRYPOINT ["gospoof"]
