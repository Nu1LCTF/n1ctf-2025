FROM golang AS builder

WORKDIR /build

COPY . .

RUN go build -o sp main.go

FROM debian:bookworm-slim

RUN apt update && apt install -y openssl

WORKDIR /app

COPY --from=builder /build/sp ./
COPY run.sh ./

EXPOSE 9000

CMD ["bash", "/app/run.sh"]
