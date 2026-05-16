"""
Basic unit tests for the packet parser logic in main.py
Run with:  pytest tests/
"""

import struct
import socket
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from main import parse_packet


# ── Helpers to build raw Ethernet frames ──────────────────────────────────────

def _build_ethernet(payload: bytes, eth_type: int = 0x0800) -> bytes:
    src_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
    dst_mac = b"\x11\x22\x33\x44\x55\x66"
    return dst_mac + src_mac + struct.pack("!H", eth_type) + payload


def _build_ipv4(proto: int, src: str, dst: str, payload: bytes) -> bytes:
    src_bytes = socket.inet_aton(src)
    dst_bytes = socket.inet_aton(dst)
    total_len = 20 + len(payload)
    # Minimal IPv4 header (IHL=5, no options)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,       # version + IHL
        0,          # DSCP/ECN
        total_len,
        0,          # ID
        0,          # flags + fragment offset
        64,         # TTL
        proto,      # protocol
        0,          # checksum (0 = ignored by dpkt parser)
        src_bytes,
        dst_bytes,
    )
    return header + payload


def _build_tcp(sport: int, dport: int) -> bytes:
    # Minimal TCP header: 20 bytes, data offset = 5
    return struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 0x50, 0, 0, 0, 0)


def _build_udp(sport: int, dport: int, payload: bytes = b"") -> bytes:
    length = 8 + len(payload)
    return struct.pack("!HHHH", sport, dport, length, 0) + payload


def _build_icmp() -> bytes:
    # Type 8 = Echo Request
    return struct.pack("!BBHHH", 8, 0, 0, 0, 0)


# ── Tests ──────────────────────────────────────────────────────────────────────

class TestParsePacketTCP:
    def _make(self, src="1.2.3.4", dst="5.6.7.8", sport=1234, dport=80):
        tcp  = _build_tcp(sport, dport)
        ip   = _build_ipv4(6, src, dst, tcp)
        eth  = _build_ethernet(ip)
        return parse_packet(1_700_000_000.0, eth)

    def test_protocol(self):
        assert self._make()["l4_protocol"] == "tcp"

    def test_addresses(self):
        doc = self._make(src="10.0.0.1", dst="10.0.0.2")
        assert doc["src_ip"] == "10.0.0.1"
        assert doc["dst_ip"] == "10.0.0.2"

    def test_ports(self):
        doc = self._make(sport=54321, dport=443)
        assert doc["src_port"] == 54321
        assert doc["dst_port"] == 443

    def test_timestamp_present(self):
        doc = self._make()
        assert "T" in doc["timestamp"]   # ISO-8601 format

    def test_packet_length(self):
        eth = _build_ethernet(_build_ipv4(6, "1.1.1.1", "2.2.2.2", _build_tcp(1, 2)))
        doc = parse_packet(0.0, eth)
        assert doc["packet_length"] == len(eth)


class TestParsePacketUDP:
    def _make(self, sport=5353, dport=5353):
        udp = _build_udp(sport, dport, b"hello")
        ip  = _build_ipv4(17, "192.168.1.1", "192.168.1.2", udp)
        eth = _build_ethernet(ip)
        return parse_packet(0.0, eth)

    def test_protocol(self):
        assert self._make()["l4_protocol"] == "udp"

    def test_ports(self):
        doc = self._make(sport=12345, dport=53)
        assert doc["src_port"] == 12345
        assert doc["dst_port"] == 53


class TestParsePacketICMP:
    def test_protocol(self):
        icmp = _build_icmp()
        ip   = _build_ipv4(1, "8.8.8.8", "1.1.1.1", icmp)
        eth  = _build_ethernet(ip)
        doc  = parse_packet(0.0, eth)
        assert doc["l4_protocol"] == "icmp"
        assert doc["src_port"] is None
        assert doc["dst_port"] is None


class TestParsePacketNonIP:
    def test_arp_returns_other(self):
        # ARP ethertype = 0x0806
        eth = _build_ethernet(b"\x00" * 28, eth_type=0x0806)
        doc = parse_packet(0.0, eth)
        assert doc["l4_protocol"] == "other"
        assert doc["src_ip"] is None

    def test_garbage_bytes_dont_crash(self):
        doc = parse_packet(0.0, b"\xff\xfe\x00\x01")
        assert doc["l4_protocol"] == "other"
