#!/bin/bash

HOST=$(hostname -i)

PEERS=node1:$HOST:12380,node2:$HOST:22380,node3:$HOST:32380

./kvstore -id node1 -haddr 0.0.0.0:12379 -raddr $HOST:12380 -paddrs $PEERS &
./kvstore -id node2 -haddr 0.0.0.0:22379 -raddr $HOST:22380 -paddrs $PEERS &
./kvstore -id node3 -haddr 0.0.0.0:32379 -raddr $HOST:32380 -paddrs $PEERS &

sleep 5

base64 -w 0 idp-metadata.xml > idp-metadata.b64

while true; do
    curl -s -X POST "http://$HOST:12379/key/metadata" -T idp-metadata.b64 >/dev/null
    curl -s -X POST "http://$HOST:22379/key/metadata" -T idp-metadata.b64 >/dev/null
    curl -s -X POST "http://$HOST:32379/key/metadata" -T idp-metadata.b64 >/dev/null

    COUNT=0

    for PORT in 12379 22379 32379; do
        URL="http://$HOST:$PORT/key/metadata"
        RESPONSE=$(curl -s -w "\n%{http_code}" "$URL")
        STATUS_CODE=$(echo "$RESPONSE" | tail -n1)
        BODY=$(echo "$RESPONSE" | sed '$d')

        if [ "$STATUS_CODE" = "200" ] && [ -n "$BODY" ]; then
            COUNT=$((COUNT+1))
        fi
    done

    if [ $COUNT -eq 3 ]; then
        break
    fi

    sleep 1
done

sleep infinity