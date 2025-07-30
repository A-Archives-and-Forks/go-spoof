# --- Build Stage ---
FROM golang:1.22 as builder

WORKDIR /app
COPY . .

WORKDIR /app/cmd/gospoof
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /gospoof

# --- Runtime Stage ---
FROM debian:bullseye-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && \
    apt install -y curl gnupg ca-certificates build-essential sqlite3 && \
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt install -y nodejs && \
    apt clean && rm -rf /var/lib/apt/lists/*

COPY --from=builder /gospoof /usr/bin/gospoof
COPY cmd/tools /tools
COPY cmd/Web /Web

WORKDIR /Web/Server
RUN npm install express ejs express-ejs-layouts socket.io bcrypt better-sqlite3 express-rate-limit express-session validator multer

WORKDIR /
EXPOSE 3000
ENTRYPOINT ["gospoof"]
