#!/bin/sh
# Use the distribution kernel's BBR implementation; preserve the existing qdisc.
set -eu
saved=/etc/xray-gateway/tcp-congestion-control.before
case "${1:-enable}" in
enable)
    if [ ! -f "$saved" ]; then
        umask 077
        sysctl -n net.ipv4.tcp_congestion_control > "$saved"
    fi
    modprobe tcp_bbr
    sysctl -w net.ipv4.tcp_congestion_control=bbr
    printf '%s\n' tcp_bbr > /etc/modules-load.d/xray-gateway-bbr.conf
    printf '%s\n' 'net.ipv4.tcp_congestion_control = bbr' > /etc/sysctl.d/90-xray-gateway-bbr.conf
    ;;
restore)
    previous=$(cat "$saved")
    case "$previous" in *[!a-zA-Z0-9_-]*|'') exit 1;; esac
    sysctl -w "net.ipv4.tcp_congestion_control=$previous"
    rm -f /etc/modules-load.d/xray-gateway-bbr.conf /etc/sysctl.d/90-xray-gateway-bbr.conf
    ;;
*) exit 2;;
esac
