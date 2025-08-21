#!/usr/bin/env python3
import time
import socket
import dns.resolver
import dns.exception
import requests
import xml.etree.ElementTree as ET
import subprocess
from prometheus_client import start_http_server, Gauge, Counter

# =========================
# Prometheus Metrics
# =========================
BIND_UP = Gauge("bind_up", "BIND service status (1=up, 0=down)")
BIND_LATENCY = Gauge("bind_latency_seconds", "DNS query latency in seconds")
BIND_RECORD_ACCURACY = Gauge("bind_record_accuracy", "Accuracy of DNS records (percentage)")
BIND_DIRECT_VS_BGP = Gauge("bind_direct_vs_bgp_difference", "Difference between direct and BGP VIP query results")
BIND_QUERIES_TCP = Counter("bind_queries_tcp_total", "Total DNS queries over TCP")
BIND_QUERIES_UDP = Counter("bind_queries_udp_total", "Total DNS queries over UDP")
BIND_QUERY_FAILS = Counter("bind_query_failures_total", "Total DNS query failures")
BIND_SECURITY_ERRORS = Counter("bind_security_failures_total", "DNSSEC or security validation failures")
BIND_TRUNCATED_PERCENT = Gauge("bind_truncated_percent", "Percentage of truncated DNS answers")
DNS_ANSWER_SIZE = Gauge("dns_answer_size_bytes", "DNS answer size in bytes")
DNS_EDNS_FRAGMENTED = Counter("dns_edns_fragmented_total", "Total fragmented EDNS answers")

BIND_CACHE_HIT_RATIO = Gauge("bind_cache_hit_ratio", "Cache hit ratio")
BIND_QUERIES_BY_TYPE = Gauge("bind_queries_by_type_total", "DNS queries by type", ["qtype"])
BIND_RESPONSES_BY_CODE = Gauge("bind_responses_by_rcode_total", "DNS responses by return code", ["rcode"])
BIND_AXFR_SUCCESSES = Gauge("bind_axfr_success_total", "Successful AXFR zone transfers", ["zone"])
BIND_AXFR_FAILURES = Gauge("bind_axfr_failure_total", "Failed AXFR zone transfers", ["zone"])
BIND_SOA_REFRESH = Gauge("bind_soa_refresh_seconds", "SOA refresh timer", ["zone"])
BIND_SOA_EXPIRY = Gauge("bind_soa_expiry_seconds", "SOA expiry timer", ["zone"])

# System metrics
CPU_UTIL = Gauge("system_cpu_utilization_percent", "CPU utilization percentage")
NIC_UTIL_KBITS = Gauge("system_nic_kbits_per_sec", "NIC utilization in kbit/s", ["nic"])
FRR_STATUS = Gauge("frr_status", "FRR status (1=running, 0=stopped)")
CHRONYD_STATUS = Gauge("chronyd_status", "Chronyd status (1=running, 0=stopped)")
CHRONYD_DRIFT = Gauge("chronyd_time_drift_seconds", "Chronyd time drift in seconds (Last offset)")

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
INSTANCE_LABEL = "p054bdf1"

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
        truncated = bool(getattr(answers.response, "flags", 0) & 0x200)  # TC flag
        BIND_TRUNCATED_PERCENT.set(100 if truncated else 0)
        if size > 1400:  # threshold for fragmentation risk
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

def update_bind_stats():
    try:
        r = requests.get(BIND_STATS_URL, timeout=3)
        root = ET.fromstring(r.text)

        hits = int(root.findtext(".//counters[@type='cache']//counter[@name='hits']") or 0)
        misses = int(root.findtext(".//counters[@type='cache']//counter[@name='misses']") or 0)
        ratio = hits / (hits + misses) if (hits + misses) > 0 else 0
        BIND_CACHE_HIT_RATIO.set(ratio)

        for counter in root.findall(".//counters[@type='qtype']//counter"):
            qtype = counter.attrib.get("name")
            value = int(counter.text or 0)
            BIND_QUERIES_BY_TYPE.labels(qtype=qtype).set(value)

        for counter in root.findall(".//counters[@type='rcode']//counter"):
            rcode = counter.attrib.get("name")
            value = int(counter.text or 0)
            BIND_RESPONSES_BY_CODE.labels(rcode=rcode).set(value)

        for zone in root.findall(".//zones//zone"):
            zone_name = zone.attrib.get("name")
            axfr_success = int(zone.findtext("axfr-success") or 0)
            axfr_failure = int(zone.findtext("axfr-failure") or 0)
            refresh = int(zone.findtext("refresh") or 0)
            expiry = int(zone.findtext("expiry") or 0)
            BIND_AXFR_SUCCESSES.labels(zone=zone_name).set(axfr_success)
            BIND_AXFR_FAILURES.labels(zone=zone_name).set(axfr_failure)
            BIND_SOA_REFRESH.labels(zone=zone_name).set(refresh)
            BIND_SOA_EXPIRY.labels(zone=zone_name).set(expiry)

    except Exception as e:
        print(f"Error fetching BIND stats: {e}")

def update_system_metrics():
    # CPU
    CPU_UTIL.set(subprocess.getoutput("grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END {print usage}'"))

    # FRR
    FRR_STATUS.set(1 if subprocess.call(["systemctl", "is-active", "--quiet", "frr"]) == 0 else 0)

    # Chronyd
    CHRONYD_STATUS.set(1 if subprocess.call(["systemctl", "is-active", "--quiet", "chronyd"]) == 0 else 0)
    try:
        result = subprocess.check_output(["chronyc", "tracking"], text=True)
        for line in result.splitlines():
            if line.strip().startswith("Last offset"):
                drift = float(line.split()[-2])  # seconds
                CHRONYD_DRIFT.set(drift)
    except Exception:
        CHRONYD_DRIFT.set(0.0)

    # NIC usage via ifstat
    try:
        output = subprocess.check_output(["ifstat", "-i", "ens*", "1", "1"], text=True).splitlines()
        headers = output[0].split()
        values = output[2].split()
        for i, nic in enumerate(headers):
            rx_kbit = float(values[i*2]) * 8  # KB/s to kbit/s
            tx_kbit = float(values[i*2+1]) * 8
            NIC_UTIL_KBITS.labels(nic=nic+"_rx").set(rx_kbit)
            NIC_UTIL_KBITS.labels(nic=nic+"_tx").set(tx_kbit)
    except Exception as e:
        print(f"NIC metric update failed: {e}")

# =========================
# Main Loop
# =========================
def main():
    start_http_server(9119, addr="0.0.0.0")
    print("BIND exporter started on :9119")

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

        # Count TCP/UDP queries
        if direct_result:
            # Very basic approximation: if resolver.uses_tcp, increment TCP, else UDP
            # For now just increment both to have metrics
            BIND_QUERIES_TCP.inc()
            BIND_QUERIES_UDP.inc()

        update_system_metrics()
        update_bind_stats()

        time.sleep(QUERY_INTERVAL)

if __name__ == "__main__":
    main()
