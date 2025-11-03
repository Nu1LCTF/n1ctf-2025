#!/bin/bash

echo $FLAG > /flag
unset FLAG

HOST=$(hostname -i)

if [ -n "$IN_DOCKER" ]; then
    TARGET_HOST="proxy"
else
    TARGET_HOST=$HOST
fi

openssl req -x509 -newkey rsa:2048 -keyout sp.key -out sp.crt -days 365 -nodes -subj "/CN=SP"

./sp -addr 0.0.0.0:9000 -url http://$HOST:9000 -cert sp.crt -key sp.key -endpoint http://$TARGET_HOST:2379