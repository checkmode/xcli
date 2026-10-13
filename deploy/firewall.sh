#!/bin/sh
set -eu
case "${1:-start}" in
start)
    iptables -w -N XG_IN 2>/dev/null || true
    iptables -w -F XG_IN
    iptables -w -A XG_IN -p tcp -m multiport --dports 80,443 -j ACCEPT
    iptables -w -C INPUT -j XG_IN 2>/dev/null || iptables -w -I INPUT 1 -j XG_IN
    # Defense in depth: even DNS rebinding cannot reach the VCN or metadata.
    iptables -w -N XG_OUT 2>/dev/null || true
    iptables -w -F XG_OUT
    iptables -w -A XG_OUT -d 127.0.0.53/32 -p udp --dport 53 -j RETURN
    iptables -w -A XG_OUT -d 127.0.0.53/32 -p tcp --dport 53 -j RETURN
    iptables -w -A XG_OUT -d 127.0.0.1/32 -p tcp -m multiport --dports 10085,10080,10443 -j RETURN
    for net in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4 203.0.113.2/32; do iptables -w -A XG_OUT -d "$net" -j REJECT; done
    iptables -w -C OUTPUT -m owner --uid-owner xgateway -m conntrack --ctstate NEW -j XG_OUT 2>/dev/null || iptables -w -I OUTPUT 1 -m owner --uid-owner xgateway -m conntrack --ctstate NEW -j XG_OUT
    ip6tables -w -C OUTPUT -m owner --uid-owner xgateway -m conntrack --ctstate NEW -j REJECT 2>/dev/null || ip6tables -w -I OUTPUT 1 -m owner --uid-owner xgateway -m conntrack --ctstate NEW -j REJECT
    ;;
stop)
    iptables -w -D INPUT -j XG_IN 2>/dev/null || true
    iptables -w -D OUTPUT -m owner --uid-owner xgateway -m conntrack --ctstate NEW -j XG_OUT 2>/dev/null || true
    ip6tables -w -D OUTPUT -m owner --uid-owner xgateway -m conntrack --ctstate NEW -j REJECT 2>/dev/null || true
    iptables -w -F XG_IN 2>/dev/null || true
    iptables -w -X XG_IN 2>/dev/null || true
    iptables -w -F XG_OUT 2>/dev/null || true
    iptables -w -X XG_OUT 2>/dev/null || true
    ;;
*) exit 2;;
esac
