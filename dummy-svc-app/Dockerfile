# Build stage
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY main.go .
RUN CGO_ENABLED=0 GOOS=linux go build -o dummy-svc-app main.go

# Run stage
FROM alpine:3.18
WORKDIR /
COPY --from=builder /app/dummy-svc-app /dummy-svc-app
EXPOSE 8080
ENTRYPOINT ["/dummy-svc-app"]
