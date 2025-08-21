#!/usr/bin/env python3
import time
import socket
import dns.resolver
import dns.exception
import requests
import xml.etree.ElementTree as ET
import psutil
import subprocess
from prometheus_client import start_http_server, Gauge, Counter

# =========================
# Configuration
# =========================
DNS_TEST_RECORD = "P054ADSAMDC01.amer.EPIQCORP.COM"
DNS_TEST_TYPE = "A"
DIRECT_DNS = "127.0.0.1"
BGP_DNS = "10.255.0.10"
QUERY_INTERVAL = 10  # seconds
BIND_STATS_URL = "http://127.0.0.1:8053/"
EXPECTED_IPS = {"10.35.33.13"}  # Known correct IP(s)

NIC_INTERFACE = "ens33"  # NIC to monitor

# =========================
# Prometheus Metrics
# =========================
# BIND metrics
BIND_UP = Gauge("bind_up", "BIND service status (1=up, 0=down)")
BIND_LATENCY = Gauge("bind_latency_seconds", "DNS query latency in seconds")
BIND_RECORD_ACCURACY = Gauge("bind_record_accuracy", "Accuracy of DNS records (percentage)")
BIND_DIRECT_VS_BGP = Gauge("bind_direct_vs_bgp_difference", "Difference between direct and BGP VIP query results")
BIND_QUERIES = Counter("bind_queries_total", "Total DNS queries")
BIND_QUERY_FAILS = Counter("bind_query_failures_total", "Total DNS query failures")
BIND_SECURITY_ERRORS = Counter("bind_security_failures_total", "DNSSEC or security validation failures")
BIND_TRUNCATED_PERCENT = Gauge("bind_truncated_percent", "Percentage of truncated DNS answers")
DNS_ANSWER_SIZE = Gauge("dns_answer_size_bytes", "DNS answer size in bytes")
DNS_EDNS_FRAGMENTED = Counter("dns_edns_fragmented_total", "Total fragmented EDNS answers")

# System metrics
CPU_UTIL = Gauge("system_cpu_utilization_percent", "CPU utilization percentage")
FRR_STATUS = Gauge("frr_status", "FRR status (1=running, 0=stopped)")
CHRONYD_STATUS = Gauge("chronyd_status", "Chronyd status (1=running, 0=stopped)")
CHRONYD_DRIFT = Gauge("chronyd_time_drift_seconds", "Chronyd time drift in seconds (Last offset)")

# NIC metrics (RX/TX KB/s)
NIC_RX_KBPS = Gauge(f"system_nic_{NIC_INTERFACE}_rx_kbytes_per_sec",
                    f"NIC {NIC_INTERFACE} RX traffic in KB/s")
NIC_TX_KBPS = Gauge(f"system_nic_{NIC_INTERFACE}_tx_kbytes_per_sec",
                    f"NIC {NIC_INTERFACE} TX traffic in KB/s")

# =========================
# DNS Functions
# =========================
def query_dns(server_ip, hostname, qtype):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [server_ip]
    resolver.timeout = 2
    resolver.lifetime = 2
    start_time = time.time()
    try:
        answers = resolver.resolve(hostname, qtype)
        latency = time.time() - start_time
        size = sum(len(str(rdata).encode()) for rdata in answers)
        DNS_ANSWER_SIZE.set(size)
        truncated = bool(getattr(answers.response, "flags", 0) & 0x200)  # TC flag
        BIND_TRUNCATED_PERCENT.set(100 if truncated else 0)
        return [str(rdata) for rdata in answers], latency, None
    except dns.resolver.NXDOMAIN:
        return None, None, "NXDOMAIN"
    except dns.resolver.Timeout:
        return None, None, "TIMEOUT"
    except dns.exception.DNSException as e:
        return None, None, str(e)

def check_bind_health():
    try:
        sock = socket.create_connection((DIRECT_DNS, 53), timeout=2)
        sock.close()
        return True
    except OSError:
        return False

def update_bind_stats():
    try:
        r = requests.get(BIND_STATS_URL, timeout=3)
        root = ET.fromstring(r.text)

        hits = int(root.findtext(".//counters[@type='cache']//counter[@name='hits']") or 0)
        misses = int(root.findtext(".//counters[@type='cache']//counter[@name='misses']") or 0)
        ratio = hits / (hits + misses) if (hits + misses) > 0 else 0

    except Exception as e:
        print(f"Error fetching BIND stats: {e}")

# =========================
# System Functions
# =========================
_previous_counters = None
_previous_time = None

def update_nic_metrics():
    global _previous_counters, _previous_time

    counters = psutil.net_io_counters(pernic=True).get(NIC_INTERFACE)
    current_time = time.time()

    if counters is None:
        print(f"Interface {NIC_INTERFACE} not found")
        return

    if _previous_counters is not None and _previous_time is not None:
        elapsed = current_time - _previous_time
        rx_kb_s = (counters.bytes_recv - _previous_counters.bytes_recv) / 1024 / elapsed
        tx_kb_s = (counters.bytes_sent - _previous_counters.bytes_sent) / 1024 / elapsed
        NIC_RX_KBPS.set(rx_kb_s)
        NIC_TX_KBPS.set(tx_kb_s)

    _previous_counters = counters
    _previous_time = current_time

def update_system_metrics():
    CPU_UTIL.set(psutil.cpu_percent())

    frr_running = subprocess.call(["systemctl", "is-active", "--quiet", "frr"]) == 0
    FRR_STATUS.set(1 if frr_running else 0)

    chronyd_running = subprocess.call(["systemctl", "is-active", "--quiet", "chronyd"]) == 0
    CHRONYD_STATUS.set(1 if chronyd_running else 0)

    try:
        result = subprocess.check_output(["chronyc", "tracking"], text=True)
        for line in result.splitlines():
            if line.strip().startswith("Last offset"):
                drift = float(line.split()[-2])
                CHRONYD_DRIFT.set(drift)
    except Exception:
        CHRONYD_DRIFT.set(0.0)

# =========================
# Main Loop
# =========================
def main():
    start_http_server(9119, addr="0.0.0.0")
    print("BIND + NIC exporter started on :9119")

    while True:
        BIND_UP.set(1 if check_bind_health() else 0)

        direct_result, direct_latency, direct_err = query_dns(DIRECT_DNS, DNS_TEST_RECORD, DNS_TEST_TYPE)
        bgp_result, _, _ = query_dns(BGP_DNS, DNS_TEST_RECORD, DNS_TEST_TYPE)

        if direct_result:
            BIND_LATENCY.set(direct_latency)
            accuracy = len(set(direct_result) & EXPECTED_IPS) / len(EXPECTED_IPS) * 100
        else:
            accuracy = 0
            BIND_QUERY_FAILS.inc()

        BIND_RECORD_ACCURACY.set(accuracy)
        diff = 0 if direct_result and bgp_result and set(direct_result) == set(bgp_result) else 1
        BIND_DIRECT_VS_BGP.set(diff)

        if direct_err and "DNSSEC" in direct_err.upper():
            BIND_SECURITY_ERRORS.inc()

        BIND_QUERIES.inc()

        update_nic_metrics()
        update_system_metrics()
        update_bind_stats()

        time.sleep(QUERY_INTERVAL)

if __name__ == "__main__":
    main()
