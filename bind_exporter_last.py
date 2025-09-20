#!/usr/bin/env python3
import time
import socket
import re
import dns.resolver
import dns.exception
import requests
import xml.etree.ElementTree as ET
import psutil
import subprocess
from datetime import datetime
from prometheus_client import start_http_server, Gauge, Counter

# =========================
# Configuration
# =========================
DNS_TEST_RECORD = "P054ADSAMDC01.amer.EPIQCORP.COM"
DNS_TEST_TYPE = "A"
DIRECT_DNS = "127.0.0.1"
QUERY_INTERVAL = 10  # seconds
BIND_STATS_URL = "http://127.0.0.1:8053/xml/v3"
EXPECTED_IPS = {"10.35.33.13"}
IFACE_NAME = "ens33"
LOG_PATH = "/var/log/named/default.log"
DISK_PATH = "/"  # disk to monitor

# =========================
# Prometheus Metrics
# =========================
BIND_UP = Gauge("bind_up", "BIND service status (1=up, 0=down)")
BIND_LATENCY = Gauge("bind_latency_seconds", "DNS query latency in seconds")
BIND_RECORD_ACCURACY = Gauge("bind_record_accuracy", "Accuracy of DNS records (percentage)")
BIND_DIRECT_VS_BGP = Gauge("bind_direct_vs_bgp_difference", "Difference between direct and BGP VIP query results")
BIND_DIRECT_VS_BGP_MISMATCHES = Counter("bind_direct_vs_bgp_mismatches_total", "Total mismatches between direct and BGP results")
BIND_QUERY_FAILS = Counter("bind_query_failures_total", "Total DNS query failures")
BIND_SECURITY_ERRORS = Counter("bind_security_failures_total", "DNSSEC or security validation failures")

BIND_TRUNCATED_PERCENT = Gauge("bind_truncated_percent", "Percentage of truncated DNS answers (last query)")
BIND_TRUNCATED_TOTAL = Gauge("bind_truncated_total", "Total truncated DNS answers (from BIND stats)")

DNS_ANSWER_SIZE = Gauge("dns_answer_size_bytes", "DNS answer size in bytes")
DNS_EDNS_FRAGMENTED = Counter("dns_edns_fragmented_total", "Total fragmented EDNS answers")
BIND_CACHE_HIT_RATIO = Gauge("bind_cache_hit_ratio", "Cache hit ratio")
BIND_QUERIES_BY_TYPE = Gauge("bind_queries_by_type_total", "DNS queries by type", ["qtype"])
BIND_RESPONSES_BY_CODE = Gauge("bind_responses_by_rcode_total", "DNS responses by return code", ["rcode"])
BIND_AXFR_SUCCESSES = Gauge("bind_axfr_success_total", "Successful AXFR zone transfers", ["zone"])
BIND_AXFR_FAILURES = Gauge("bind_axfr_failure_total", "Failed AXFR zone transfers", ["zone"])
BIND_SOA_REFRESH = Gauge("bind_soa_refresh_seconds", "SOA refresh timer", ["zone"])
BIND_SOA_EXPIRY = Gauge("bind_soa_expiry_seconds", "SOA expiry timer", ["zone"])
BIND_QUERIES_UDP = Gauge("bind_queries_udp_total", "Total DNS queries over UDP (from stats)")
BIND_QUERIES_TCP = Gauge("bind_queries_tcp_total", "Total DNS queries over TCP (from stats)")

BIND_SERVFAIL_TOTAL = Counter("bind_servfail_total", "Total SERVFAIL events found in logs")
BIND_SERVFAIL_LAST = Gauge("bind_servfail_last_timestamp", "Timestamp of last SERVFAIL event (Unix epoch seconds)")

CPU_UTIL = Gauge("system_cpu_utilization_percent", "CPU utilization percentage")
MEM_UTIL = Gauge("system_memory_utilization_percent", "Memory utilization percentage")
SWAP_UTIL = Gauge("system_swap_utilization_percent", "Swap utilization percentage")
DISK_UTIL = Gauge("system_disk_utilization_percent", "Disk utilization percentage")
FRR_STATUS = Gauge("frr_status", "FRR status (1=running, 0=stopped)")
CHRONYD_STATUS = Gauge("chronyd_status", "Chronyd status (1=running, 0=stopped)")
CHRONYD_DRIFT = Gauge("chronyd_time_drift_seconds", "Chronyd time drift in seconds (Last offset)")
CHRONYD_STRATUM = Gauge("chronyd_stratum", "Chronyd/NTP stratum")

BIND_ZONE_COUNT = Gauge("bind_zone_count", "Number of zones currently loaded")
BIND_UPTIME = Gauge("bind_uptime_seconds", "BIND uptime in seconds")
BIND_QRY_AUTHORITATIVE = Gauge("bind_queries_authoritative_total", "Total authoritative queries from stats")
BIND_QRY_RECURSIVE = Gauge("bind_queries_recursive_total", "Total recursive queries from stats")

NIC_RX = Gauge("system_nic_rx_kbytes_per_sec", "NIC RX KB/s (ifstat)")
NIC_TX = Gauge("system_nic_tx_kbytes_per_sec", "NIC TX KB/s (ifstat)")

# Single BGP uptime metric in minutes
BGP_SESSION_UPTIME = Gauge("bgp_session_uptime_minutes", "BGP session uptime in minutes")

# =========================
# DNS Helpers
# =========================
def query_dns(server_ip, hostname, qtype, use_tcp=False):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [server_ip]
    resolver.timeout = 2
    resolver.lifetime = 2
    start_time = time.time()
    try:
        answers = resolver.resolve(hostname, qtype, tcp=use_tcp)
        latency = time.time() - start_time
        size = sum(len(str(rdata).encode()) for rdata in answers)
        DNS_ANSWER_SIZE.set(size)

        truncated = bool(getattr(answers.response, "flags", 0) & 0x200)
        BIND_TRUNCATED_PERCENT.set(100 if truncated else 0)

        if size > 1400:
            DNS_EDNS_FRAGMENTED.inc()
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

# =========================
# BGP Uptime Parsing
# =========================
def parse_uptime_to_minutes(uptime_str: str) -> int:
    total_minutes = 0
    try:
        m = re.search(r'(\d+)w', uptime_str)
        if m: total_minutes += int(m.group(1)) * 7 * 24 * 60
        m = re.search(r'(\d+)d', uptime_str)
        if m: total_minutes += int(m.group(1)) * 24 * 60
        m = re.search(r'(\d+)h', uptime_str)
        if m: total_minutes += int(m.group(1)) * 60
        m = re.search(r'(\d+)m', uptime_str)
        if m: total_minutes += int(m.group(1))
    except Exception:
        pass
    return total_minutes

_last_bgp_check = None
def update_bgp_uptime():
    global _last_bgp_check
    now = time.time()
    if _last_bgp_check is not None and now - _last_bgp_check < 300:
        return
    _last_bgp_check = now

    try:
        output = subprocess.check_output(
            ["/usr/bin/vtysh", "-c", "show ip bgp sum"],
            text=True,
            stderr=subprocess.STDOUT
        ).splitlines()
        lines = [l for l in output if l.strip()]
        if len(lines) < 9:
            BGP_SESSION_UPTIME.set(0)
            return
        uptime_str = lines[8].split()[8]  # line 9, column 9
        minutes = parse_uptime_to_minutes(uptime_str)
        BGP_SESSION_UPTIME.set(minutes)
    except Exception as e:
        print(f"[bgp-uptime] Error: {e}")
        BGP_SESSION_UPTIME.set(0)

# =========================
# NIC Metrics
# =========================
_last_nic_counters = None
_last_nic_time = None
def update_nic_metrics_ifstat():
    global _last_nic_counters, _last_nic_time
    try:
        counters = psutil.net_io_counters(pernic=True).get(IFACE_NAME)
        now = time.time()
        if counters is None:
            return
        if _last_nic_counters is not None and _last_nic_time is not None:
            interval = now - _last_nic_time
            rx_kbps = (counters.bytes_recv - _last_nic_counters.bytes_recv) / 1024 / interval
            tx_kbps = (counters.bytes_sent - _last_nic_counters.bytes_sent) / 1024 / interval
            NIC_RX.set(rx_kbps)
            NIC_TX.set(tx_kbps)
        _last_nic_counters = counters
        _last_nic_time = now
    except Exception as e:
        print(f"[nic-psutil] Error: {e}")

# =========================
# Main Loop
# =========================
def main():
    start_http_server(9119, addr="0.0.0.0")
    print(f"Exporter started on port 9119, monitoring interface: {IFACE_NAME}")

    while True:
        BIND_UP.set(1 if check_bind_health() else 0)

        udp_result, udp_latency, udp_err = query_dns(DIRECT_DNS, DNS_TEST_RECORD, DNS_TEST_TYPE, use_tcp=False)
        tcp_result, tcp_latency, tcp_err = query_dns(DIRECT_DNS, DNS_TEST_RECORD, DNS_TEST_TYPE, use_tcp=True)

        if udp_result:
            BIND_LATENCY.set(udp_latency)
            accuracy = len(set(udp_result) & EXPECTED_IPS) / len(EXPECTED_IPS) * 100
        else:
            accuracy = 0
        BIND_RECORD_ACCURACY.set(accuracy)

        if udp_result is None or udp_err:
            BIND_QUERY_FAILS.inc()
        if tcp_result is None or tcp_err:
            BIND_QUERY_FAILS.inc()

        if udp_result and tcp_result:
            if set(udp_result) != set(tcp_result):
                BIND_DIRECT_VS_BGP.set(1)
                BIND_DIRECT_VS_BGP_MISMATCHES.inc()
                BIND_QUERY_FAILS.inc()
            else:
                BIND_DIRECT_VS_BGP.set(0)
        else:
            BIND_DIRECT_VS_BGP.set(1)
            BIND_DIRECT_VS_BGP_MISMATCHES.inc()
            BIND_QUERY_FAILS.inc()

        if udp_err and "DNSSEC" in udp_err.upper():
            BIND_SECURITY_ERRORS.inc()

        update_nic_metrics_ifstat()
        update_bgp_uptime()
        time.sleep(QUERY_INTERVAL)

if __name__ == "__main__":
    main()
