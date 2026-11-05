"""Resolve a new installation domain and detect a usable local IPv6 address."""
import ipaddress
import json
import socket
import subprocess


def resolve_domain(domain, ipv4):
    def resolve(family):
        try:
            return {str(ipaddress.ip_address(row[4][0].split('%', 1)[0]))
                    for row in socket.getaddrinfo(domain, 443, family, socket.SOCK_STREAM)}
        except socket.gaierror:
            return set()

    if resolve(socket.AF_INET) != {ipv4}:
        raise ValueError('面板域名的 A 记录必须仅指向本机公网 IPv4')
    ipv6 = resolve(socket.AF_INET6)
    if not ipv6:
        return False
    try:
        interfaces = json.loads(subprocess.check_output(['ip', '-j', '-6', 'addr', 'show', 'scope', 'global'],
                                                         timeout=10))
        assigned = {str(ipaddress.IPv6Address(row['local'])) for interface in interfaces
                    for row in interface.get('addr_info', []) if row.get('family') == 'inet6'
                    and row.get('local') and 'tentative' not in row.get('flags', [])
                    and 'dadfailed' not in row.get('flags', [])}
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError) as error:
        raise ValueError('无法检查本机 IPv6 地址') from error
    if not ipv6.issubset(assigned):
        raise ValueError('面板域名的 AAAA 记录必须指向本机 IPv6 地址')
    return True
