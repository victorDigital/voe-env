#!/bin/sh
set -eu

if [ -z "${DATABASE_URL:-}" ]; then
  database_password=$(cat /run/voe/password)
  export DATABASE_URL="postgresql://voe:${database_password}@db:5432/voe"
fi

if [ -z "${ORIGIN:-}" ] && [ -n "${BETTER_AUTH_URL:-}" ]; then
  export ORIGIN="$BETTER_AUTH_URL"
fi

exec "$@"
