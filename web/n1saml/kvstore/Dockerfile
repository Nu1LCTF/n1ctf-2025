FROM golang AS builder

WORKDIR /build

COPY . .

RUN go build -o kvstore main.go

FROM debian:bookworm-slim

RUN apt update && apt install -y curl

WORKDIR /app

COPY --from=builder /build/kvstore ./
COPY --from=builder /build/idp-metadata.xml ./
COPY run.sh ./

EXPOSE 12379 12380 22379 22380 32379 32380

CMD ["bash", "/app/run.sh"]
