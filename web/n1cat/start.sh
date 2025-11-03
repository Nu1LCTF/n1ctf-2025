#!/bin/bash
if [ -n "$FLAG" ]; then
  echo $FLAG > /flag
else
  echo "hh";
fi

catalina.sh run