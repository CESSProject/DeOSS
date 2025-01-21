FROM golang:1.22-alpine3.18 AS builder

ARG go_proxy
ENV GOPROXY ${go_proxy}

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o oss cmd/main.go

FROM alpine:3.18 AS runner
WORKDIR /app
ENV PATH="/app:${PATH}"
COPY --from=builder /app/oss /app/
