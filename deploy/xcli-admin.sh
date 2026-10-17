#!/bin/sh
# Keep Python caches out of immutable release directories, including older helpers.
set -eu
exec /usr/bin/python3 -B /opt/xcli/current/scripts/gatewayctl.py "$@"
