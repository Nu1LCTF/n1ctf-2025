FROM golang AS builder

WORKDIR /build

COPY . .

RUN go build -o healthcheck main.go

FROM debian:bookworm-slim

RUN apt update && \
    apt install -y curl && \
    groupadd -r ctf && \
    useradd -m -r -g ctf ctf && \
    mkdir /app/ && \
    chown -R ctf:ctf /app/

WORKDIR /app

COPY --from=builder /build/healthcheck ./
COPY run.sh ./

EXPOSE 8000

CMD ["bash", "/app/run.sh"]
