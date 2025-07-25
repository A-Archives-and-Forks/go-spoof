# -------- Stage 1: Build GoSpoof binary --------
FROM golang:1.22 as builder

WORKDIR /app
COPY . .

# Build the GoSpoof binary from cmd/gospoof
RUN cd cmd/gospoof && go build -o /gospoof

#Stage 2: Minimal runtime image
FROM debian:bullseye-slim

# Prevent apt from asking questions (just in case)
ENV DEBIAN_FRONTEND=noninteractive

# Copy binary from builder
COPY --from=builder /gospoof /usr/bin/gospoof

ENTRYPOINT ["gospoof"]
