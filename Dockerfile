# Build stage
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache gcc musl-dev

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=1 go build -ldflags="-X github.com/tatlilimon/proxier/internal/server.Version=${VERSION}" -o proxier ./cmd/proxier/

# Runtime stage
FROM alpine:3.21

RUN apk add --no-cache ca-certificates

WORKDIR /app
COPY --from=builder /app/proxier .
COPY --from=builder /app/config.yaml .

RUN mkdir -p /data
ENV STORAGE_PATH=/data/proxies.db

EXPOSE 8080

ENTRYPOINT ["./proxier"]
