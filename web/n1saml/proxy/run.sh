#!/bin/bash

HOST=$(hostname -i)

if [ -n "$IN_DOCKER" ]; then
    TARGET_HOST="kvstore"
else
    TARGET_HOST=$HOST
fi

./proxy -urls http://$TARGET_HOST:12379,http://$TARGET_HOST:22379,http://$TARGET_HOST:32379 -addr 0.0.0.0:2379