"""Tests for URL safety and SSRF protection."""

import ipaddress

import pytest

from app.services.url_safety import (
    BLOCKED_NETWORKS,
    is_ip_blocked,
    is_blocked_host,
    is_safe_public_url,
    validate_ip_at_connect_time,
)


class TestIsIpBlocked:
    def test_loopback_blocked(self):
        assert is_ip_blocked(ipaddress.ip_address("127.0.0.1"))

    def test_private_10_blocked(self):
        assert is_ip_blocked(ipaddress.ip_address("10.0.0.1"))

    def test_private_172_blocked(self):
        assert is_ip_blocked(ipaddress.ip_address("172.16.0.1"))

    def test_private_192_blocked(self):
        assert is_ip_blocked(ipaddress.ip_address("192.168.1.1"))

    def test_link_local_blocked(self):
        assert is_ip_blocked(ipaddress.ip_address("169.254.1.1"))

    def test_public_ip_allowed(self):
        assert not is_ip_blocked(ipaddress.ip_address("8.8.8.8"))

    def test_cloudflare_allowed(self):
        assert not is_ip_blocked(ipaddress.ip_address("1.1.1.1"))

    def test_multicast_blocked(self):
        assert is_ip_blocked(ipaddress.ip_address("224.0.0.1"))

    def test_reserved_0_blocked(self):
        assert is_ip_blocked(ipaddress.ip_address("0.0.0.0"))

    def test_ipv6_loopback_blocked(self):
        assert is_ip_blocked(ipaddress.ip_address("::1"))

    def test_ipv6_private_blocked(self):
        assert is_ip_blocked(ipaddress.ip_address("fc00::1"))


class TestValidateIpAtConnectTime:
    def test_safe_ip_returns_true(self):
        assert validate_ip_at_connect_time("8.8.8.8") is True

    def test_blocked_ip_returns_false(self):
        assert validate_ip_at_connect_time("127.0.0.1") is False

    def test_hostname_returns_true(self):
        # Cannot resolve hostname to IP at validation time
        assert validate_ip_at_connect_time("example.com") is True


class TestIsSafePublicUrl:
    def test_http_url_safe(self):
        assert is_safe_public_url("https://example.com") is True

    def test_file_url_blocked(self):
        assert is_safe_public_url("file:///etc/passwd") is False

    def test_no_hostname_blocked(self):
        assert is_safe_public_url("https://") is False

    def test_empty_string_blocked(self):
        assert is_safe_public_url("") is False

    def test_ftp_blocked(self):
        assert is_safe_public_url("ftp://example.com") is False


class TestBlockedNetworks:
    def test_all_networks_are_valid(self):
        for net in BLOCKED_NETWORKS:
            assert isinstance(net, ipaddress.IPv4Network | ipaddress.IPv6Network)

    def test_loopback_in_blocked(self):
        loopback = ipaddress.ip_network("127.0.0.0/8")
        assert loopback in BLOCKED_NETWORKS

    def test_private_10_in_blocked(self):
        private = ipaddress.ip_network("10.0.0.0/8")
        assert private in BLOCKED_NETWORKS
