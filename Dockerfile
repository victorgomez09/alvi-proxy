FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY . .
RUN go mod download
RUN go build -o viprox cmd/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/viprox .
COPY config.yaml .

EXPOSE 8080 8081 9090
CMD ["./viprox", "--config", "config.yaml"]
