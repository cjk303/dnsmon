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
# Prometheus Metrics
# =========================
BIND_UP = Gauge('bind_up', 'BIND service status (1=up, 0=down)')
BIND_LATENCY = Gauge('bind_latency_seconds', 'DNS query latency in seconds')
BIND_RECORD_ACCURACY = Gauge('bind_record_accuracy', 'Accuracy of DNS records (percentage)')
BIND_DIRECT_VS_BGP = Gauge('bind_direct_vs_bgp_difference', 'Difference between direct and BGP VIP query results')
BIND_QUERIES = Counter('bind_queries_total', 'Total DNS queries')
BIND_QUERY_FAILS = Counter('bind_query_failures_total', 'Total DNS query failures')
BIND_SECURITY_ERRORS = Counter('bind_security_failures_total', 'DNSSEC or security validation failures')
BIND_TRUNCATED_PERCENT = Gauge('bind_truncated_percent', 'Percentage of truncated DNS answers')
DNS_ANSWER_SIZE = Gauge('dns_answer_size_bytes', 'DNS answer size in bytes')
DNS_EDNS_FRAGMENTED = Counter('dns_edns_fragmented_total', 'Total fragmented EDNS answers')

BIND_CACHE_HIT_RATIO = Gauge("bind_cache_hit_ratio", "Cache hit ratio")
BIND_QUERIES_BY_TYPE = Counter("bind_queries_by_type_total", "DNS queries by type", ["qtype"])
BIND_QUERIES_BY_TRANSPORT = Counter("bind_queries_by_transport_total", "DNS queries by transport", ["transport"])
BIND_RESPONSES_BY_CODE = Counter("bind_responses_by_rcode_total", "DNS responses by return code", ["rcode"])
BIND_AXFR_SUCCESSES = Counter("bind_axfr_success_total", "Successful AXFR zone transfers", ["zone"])
BIND_AXFR_FAILURES = Counter("bind_axfr_failure_total", "Failed AXFR zone transfers", ["zone"])
BIND_SOA_REFRESH = Gauge("bind_soa_refresh_seconds", "SOA refresh timer", ["zone"])
BIND_SOA_EXPIRY = Gauge("bind_soa_expiry_seconds", "SOA expiry timer", ["zone"])

# System metrics
CPU_UTIL = Gauge("system_cpu_utilization_percent", "CPU utilization percentage")
NIC_UTIL = Gauge("system_nic_utilization_percent", "NIC utilization percentage", ["nic"])
FRR_STATUS = Gauge("frr_status", "FRR status (1=running, 0=stopped)")
CHRONYD_STATUS = Gauge("chronyd_status", "Chronyd status (1=running, 0=stopped)")
CHRONYD_DRIFT = Gauge("chronyd_time_drift_seconds", "Chronyd time drift in seconds")

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

# =========================
# Functions
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
        truncated = any([getattr(answers.response, 'flags', 0) & 0x200])  # TC flag check
        BIND_TRUNCATED_PERCENT.set(100 if truncated else 0)
        if size > 1400:  # Arbitrary threshold for fragmentation risk
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
        r
