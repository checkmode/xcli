#!/bin/sh
# Keep Python caches out of immutable release directories, including older helpers.
set -eu
# Older sealed baselines still default to /root. The stable entry point owns
# storage placement while --output remains an explicit administrator choice.
if [ "${1-}" = backup ]; then
    xcli_output_set=0
    for xcli_argument do
        case "$xcli_argument" in --output|--output=*) xcli_output_set=1 ;; esac
    done
    if [ "$xcli_output_set" = 0 ]; then
        [ "$(id -u)" = 0 ] || { echo '请使用 sudo 执行。' >&2; exit 1; }
        install -d -m700 /var/backups/xcli/manual
        set -- "$@" --output "/var/backups/xcli/manual/gateway-$(date -u +%Y%m%dT%H%M%SZ)-$$.sqlite"
    fi
fi
exec /usr/bin/python3 -B /opt/xcli/current/scripts/gatewayctl.py "$@"
