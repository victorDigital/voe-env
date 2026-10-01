#!/bin/sh
set -eu

if [ ! -s /run/voe/password ]; then
  umask 077
  od -An -N32 -tx1 /dev/urandom | tr -d ' \n' > /run/voe/password.tmp
  chmod 444 /run/voe/password.tmp
  mv /run/voe/password.tmp /run/voe/password
fi

exec /usr/local/bin/docker-entrypoint.sh "$@"
