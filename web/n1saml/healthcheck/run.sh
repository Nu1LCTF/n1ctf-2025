#!/bin/bash

unset FLAG

HOST=$(hostname -i)

if [ -n "$IN_DOCKER" ]; then
    TARGET_SP_HOST="sp"
    TARGET_PROXY_HOST="proxy"
else
    TARGET_SP_HOST=$HOST
    TARGET_PROXY_HOST=$HOST
fi

URL="http://$TARGET_PROXY_HOST:2379/key/metadata"

COUNT=0

while true; do
    RESPONSE=$(curl -s -w "\n%{http_code}" "$URL")
    STATUS_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | sed '$d')

    if [ "$STATUS_CODE" = "200" ] && [ -n "$BODY" ]; then
        COUNT=$((COUNT+1))
        if [ $COUNT -ge 3 ]; then
            break
        fi
    else
        COUNT=0
    fi

    sleep 1
done

su -p ctf -c "./healthcheck -addr 0.0.0.0:8000 -url http://$TARGET_SP_HOST:9000"
