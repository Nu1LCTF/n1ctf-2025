FROM golang AS builder

WORKDIR /build

COPY . .

RUN go build -o proxy main.go

FROM debian:bookworm-slim

WORKDIR /app

COPY --from=builder /build/proxy ./
COPY run.sh ./

EXPOSE 2379

CMD ["bash", "/app/run.sh"]
