# Build stage
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X github.com/SafiullahRattar/netwatch/cmd.Version=$(git describe --tags --always --dirty 2>/dev/null || echo dev)" -o /netwatch .

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates

# Run as non-root user
RUN adduser -D -u 1000 netwatch
USER netwatch

COPY --from=builder /netwatch /usr/local/bin/netwatch

ENTRYPOINT ["netwatch"]
CMD ["--help"]
