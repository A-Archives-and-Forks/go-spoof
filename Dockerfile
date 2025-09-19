olang:1.22 AS builder
ENV GOTOOLCHAIN=auto
WORKDIR /app

COPY cmd/gospoof/go.mod ./cmd/gospoof/
WORKDIR /app/cmd/gospoof
RUN go mod download

WORKDIR /app
COPY . .

WORKDIR /app/cmd/gospoof
RUN go mod tidy

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /gospoof

# --- Runtime stage ---
FROM debian:bullseye-slim
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y curl gnupg ca-certificates build-essential sqlite3 && \
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY --from=builder /gospoof /usr/bin/gospoof
COPY cmd/tools /tools
COPY cmd/Web /Web
RUN [ -f /Web/package.json ] && cd /Web && npm ci --omit=dev || true

ENTRYPOINT ["/usr/bin/gospoof"]
