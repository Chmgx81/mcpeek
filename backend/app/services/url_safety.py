from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from ..config import settings


BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def is_ip_blocked(ip: ipaddress.IPAddress) -> bool:
    """Check if a single IP address falls in a blocked network range."""
    return any(ip in net for net in BLOCKED_NETWORKS)


def is_blocked_host(hostname: str) -> bool:
    """Resolve hostname and check if ANY resolved IP is in a blocked range."""
    try:
        addresses = [ipaddress.ip_address(hostname)]
    except ValueError:
        try:
            infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        except socket.gaierror:
            return True
        addresses = [ipaddress.ip_address(info[4][0]) for info in infos]

    return any(is_ip_blocked(ip) for ip in addresses)


def validate_ip_at_connect_time(ip_str: str) -> bool:
    """Validate an IP address string against blocked networks.

    Use this at connection time (after DNS resolution) to prevent
    DNS rebinding attacks where the IP changes between lookup and connect.
    Returns True if the IP is safe (not blocked).
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # hostname, not IP — cannot check
    return not is_ip_blocked(ip)


def is_safe_public_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    if settings.ALLOW_PRIVATE_NETWORK_SCANS:
        return True
    return not is_blocked_host(parsed.hostname)
