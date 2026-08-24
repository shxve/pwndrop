#!/bin/sh
set -e
if [ ! -f /data/pwndrop.ini ]; then
    echo "[entrypoint] no /data/pwndrop.ini found - seeding default config"
    mkdir -p /data
    cp /app/pwndrop.ini.default /data/pwndrop.ini
fi
exec /app/pwndrop "$@"
