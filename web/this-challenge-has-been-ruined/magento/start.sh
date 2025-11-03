#!/bin/bash

suffix=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 8)
echo $FLAG > /this-is-the-flag-$suffix

export FLAG="flag{}"
unset FLAG

apache2-foreground