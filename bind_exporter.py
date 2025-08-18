#!/usr/bin/env python3
import time
import socket
import dns.resolver
import dns.exception
import requests
import xml.etree.ElementTree as ET
from prometheus_client import start_http_server, Gauge, Counter

# =========================
# Prometheus Metrics
# =========================
# Probe-based metrics
BIND_UP = Gauge('bind_up', 'BIND service status (1=up, 0=down)')
BIND_LATENCY = Gauge('bind_latency_seconds', 'DNS query latency in seconds')
BIND_RECORD_ACCURACY = Gauge('bind_record_accuracy', 'Accuracy of DNS records (percentage)')
BIND_DIRECT_VS_BGP = Gauge('bind_direct_vs_bgp_difference', 'Difference between direct and BGP VIP query results')
BIND_QUERIES = Counter('bind_queries_total', 'Total DNS queries')
BIND_QUERY_FAILS = Counter('bind_query_failures_total', 'Total DNS query failures')
BIND_SECURITY_ERRORS = Counter('bind_security_failures_total', 'DNSSEC or security validation failures')

# Stats-channel metrics
BIND_CACHE_HIT_RATIO = Gauge("bind_cache_hit_ratio", "Cache hit ratio")
BIND_QUERIES_BY_TYPE = Counter("bind_queries_by_type_total", "DNS queries by type", ["qtype"])
BIND_QUERIES_BY_TRANSPORT = Counter("bind_queries_by_transport_total", "DNS queries by transport", ["transport"])
BIND_RESPONSES_BY_CODE = Counter("bind_responses_by_rcode_total", "DNS responses by return code", ["rcode"])
BIND_AXFR_SUCCESSES = Counter("bind_axfr_success_total", "Successful AXFR zone transfers", ["zone"])
BIND_AXFR_FAILURES = Counter("bind_axfr_failure_total", "Failed AXFR zone transfers", ["zone"])
BIND_SOA_REFRESH = Gauge("bind_soa_refresh_seconds", "SOA refresh timer", ["zone"])
BIND_SOA_EXPIRY = Gauge("bind_soa_expiry_seconds", "SOA expiry timer", ["zone"])

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

        # Cache hit ratio
        hits = int(root.findtext(".//counters[@type='cache']//counter[@name='hits']"))
        misses = int(root.findtext(".//counters[@type='cache']//counter[@name='misses']"))
        ratio = hits / (hits + misses) if (hits + misses) > 0 else 0
        BIND_CACHE_HIT_RATIO.set(ratio)

        # Query types
        for counter in root.findall(".//counters[@type='qtype']//counter"):
            qtype = counter.attrib.get("name")
            value = int(counter.text)
            BIND_QUERIES_BY_TYPE.labels(qtype=qtype).inc(value)

        # Transport
        for counter in root.findall(".//counters[@type='transport']//counter"):
            transport = counter.attrib.get("name")
            value = int(counter.text)
            BIND_QUERIES_BY_TRANSPORT.labels(transport=transport).inc(value)

        # Response codes
        for counter in root.findall(".//counters[@type='rcode']//counter"):
            rcode = counter.attrib.get("name")
            value = int(counter.text)
            BIND_RESPONSES_BY_CODE.labels(rcode=rcode).inc(value)

        # Zone transfers & SOA timers
        for zone in root.findall(".//zones//zone"):
            zone_name = zone.attrib.get("name")
            axfr_success = int(zone.findtext("axfr-success") or 0)
            axfr_failure = int(zone.findtext("axfr-failure") or 0)
            refresh = int(zone.findtext("refresh") or 0)
            expiry = int(zone.findtext("expiry") or 0)

            BIND_AXFR_SUCCESSES.labels(zone=zone_name).inc(axfr_success)
            BIND_AXFR_FAILURES.labels(zone=zone_name).inc(axfr_failure)
            BIND_SOA_REFRESH.labels(zone=zone_name).set(refresh)
            BIND_SOA_EXPIRY.labels(zone=zone_name).set(expiry)

    except Exception as e:
        print(f"Error fetching BIND stats: {e}")

# =========================
# Main Loop
# =========================
def main():
    start_http_server(9119, addr="0.0.0.0")
    print("BIND exporter started on :9119")

    while True:
        # Health check
        BIND_UP.set(1 if check_bind_health() else 0)

        # Direct query
        direct_result, direct_latency, direct_err = query_dns(DIRECT_DNS, DNS_TEST_RECORD, DNS_TEST_TYPE)
        bgp_result, bgp_latency, bgp_err = query_dns(BGP_DNS, DNS_TEST_RECORD, DNS_TEST_TYPE)

        # Update probe metrics
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

        # Update stats-channel metrics
        update_bind_stats()

        time.sleep(QUERY_INTERVAL)

if __name__ == "__main__":
    main()
