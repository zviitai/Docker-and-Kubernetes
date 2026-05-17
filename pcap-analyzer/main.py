"""
PCAP Analyzer Service
---------------------
Reads a .pcap / .pcapng file, writes every packet as a document to
Elasticsearch, and exposes Prometheus metrics on /metrics.

Usage:
    python main.py <path/to/file.pcap>
    # or
    PCAP_PATH=sample.pcap python main.py
"""

import os
import sys
import time
import socket
import logging
import datetime

import dpkt
from elasticsearch import Elasticsearch
from prometheus_client import Counter, start_http_server

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

# ── Config (all from environment variables) ───────────────────────────────────
ELASTIC_URL      = os.getenv("ELASTIC_URL", "http://localhost:9200")
ELASTIC_INDEX    = os.getenv("ELASTIC_INDEX", "pcap-packets")
ELASTIC_USERNAME = os.getenv("ELASTIC_USERNAME")
ELASTIC_PASSWORD = os.getenv("ELASTIC_PASSWORD")
METRICS_PORT     = int(os.getenv("METRICS_PORT", "9100"))

# ── Prometheus metrics ─────────────────────────────────────────────────────────
# These are the three required counters.
# Counter = always goes up; perfect for "how many X happened".
packets_total = Counter(
    "pcap_packets_total",
    "Total packets processed, by L4 protocol",
    ["protocol"],
)
bytes_total = Counter(
    "pcap_bytes_total",
    "Total bytes of all packets processed, by L4 protocol",
    ["protocol"],
)
elastic_writes = Counter(
    "pcap_elastic_write_total",
    "Elasticsearch write attempts",
    ["status"],   # label values: "success" or "fail"
)


# ── Packet parsing ─────────────────────────────────────────────────────────────
def _safe_inet(raw_bytes: bytes) -> str:
    """Convert raw IP bytes to dotted-decimal string safely."""
    try:
        return socket.inet_ntoa(raw_bytes)
    except Exception:
        return None


def parse_packet(ts: float, raw: bytes) -> dict:
    """
    Turn a raw packet (bytes) + unix timestamp into a flat dict
    ready to be stored as an Elasticsearch document.

    We handle:
      - Ethernet → IPv4 → TCP / UDP / ICMP
      - Non-IP frames (ARP, etc.) — stored with what we CAN extract
    """
    doc = {
        "timestamp":     datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z",
        "packet_length": len(raw),
        "src_ip":        None,
        "dst_ip":        None,
        "src_port":      None,
        "dst_port":      None,
        "l4_protocol":   "other",
    }

    try:
        eth = dpkt.ethernet.Ethernet(raw)
    except Exception:
        return doc   # can't even parse Ethernet – return what we have

    # Only IPv4 carries the fields we care about
    if not isinstance(eth.data, dpkt.ip.IP):
        return doc

    ip = eth.data
    doc["src_ip"] = _safe_inet(ip.src)
    doc["dst_ip"] = _safe_inet(ip.dst)

    if isinstance(ip.data, dpkt.tcp.TCP):
        doc["l4_protocol"] = "tcp"
        doc["src_port"]    = ip.data.sport
        doc["dst_port"]    = ip.data.dport
    elif isinstance(ip.data, dpkt.udp.UDP):
        doc["l4_protocol"] = "udp"
        doc["src_port"]    = ip.data.sport
        doc["dst_port"]    = ip.data.dport
    elif isinstance(ip.data, dpkt.icmp.ICMP):
        doc["l4_protocol"] = "icmp"

    return doc


# ── Elasticsearch write with retry ────────────────────────────────────────────
def write_to_elastic(es: Elasticsearch, index: str, doc: dict, max_retries: int = 3) -> bool:
    """
    Try to index a document up to max_retries times.
    Uses exponential back-off: 1 s → 2 s → 4 s …
    Returns True on success, False if all attempts fail.
    """
    for attempt in range(1, max_retries + 1):
        try:
            es.index(index=index, document=doc)
            elastic_writes.labels(status="success").inc()
            return True
        except Exception as exc:
            log.warning("ES write attempt %d/%d failed: %s", attempt, max_retries, exc)
            if attempt < max_retries:
                time.sleep(2 ** (attempt - 1))   # 1 s, 2 s, 4 s

    elastic_writes.labels(status="fail").inc()
    log.error("All %d write attempts failed – document dropped.", max_retries)
    return False


# ── Open pcap/pcapng transparently ───────────────────────────────────────────
def open_reader(f):
    """Return the correct dpkt reader for pcap or pcapng files."""
    magic = f.read(4)
    f.seek(0)
    # pcapng Section Block magic
    if magic == b"\x0a\x0d\x0d\x0a":
        return dpkt.pcapng.Reader(f)
    return dpkt.pcap.Reader(f)


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    # 1. Resolve pcap path
    pcap_path = sys.argv[1] if len(sys.argv) > 1 else os.getenv("PCAP_PATH")
    if not pcap_path:
        log.error("No pcap file provided. Pass path as CLI argument or set PCAP_PATH env var.")
        sys.exit(1)

    # 2. Start Prometheus /metrics server (before any work, so metrics are live from the start)
    start_http_server(METRICS_PORT)
    log.info("Prometheus metrics → http://0.0.0.0:%d/metrics", METRICS_PORT)

    # 3. Connect to Elasticsearch
    es_kwargs: dict = {"hosts": [ELASTIC_URL]}
    if ELASTIC_USERNAME and ELASTIC_PASSWORD:
        es_kwargs["basic_auth"] = (ELASTIC_USERNAME, ELASTIC_PASSWORD)
    es = Elasticsearch(**es_kwargs)
    log.info("Elasticsearch target: %s  index: %s", ELASTIC_URL, ELASTIC_INDEX)

    # 4. Read & process every packet
    log.info("Opening pcap: %s", pcap_path)
    processed = 0
    with open(pcap_path, "rb") as f:
        reader = open_reader(f)
        for ts, raw in reader:
            doc      = parse_packet(ts, raw)
            protocol = doc["l4_protocol"]

            packets_total.labels(protocol=protocol).inc()
            bytes_total.labels(protocol=protocol).inc(doc["packet_length"])

            write_to_elastic(es, ELASTIC_INDEX, doc)
            processed += 1

            if processed % 1000 == 0:
                log.info("Processed %d packets so far …", processed)

    log.info("Finished. Total packets processed: %d", processed)

    # 5. Keep the process alive so /metrics stays reachable
    log.info("Metrics server still running. Press Ctrl-C to stop.")
    while True:
        time.sleep(60)


if __name__ == "__main__":
    main()
