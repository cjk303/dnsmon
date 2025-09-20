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
BGP_DNS = "10.255.0.10"
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

# Truncation metrics
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

# SERVFAIL metrics
BIND_SERVFAIL_TOTAL = Counter("bind_servfail_total", "Total SERVFAIL events found in logs")
BIND_SERVFAIL_LAST = Gauge("bind_servfail_last_timestamp", "Timestamp of last SERVFAIL event (Unix epoch seconds)")

# System metrics
CPU_UTIL = Gauge("system_cpu_utilization_percent", "CPU utilization percentage")
MEM_UTIL = Gauge("system_memory_utilization_percent", "Memory utilization percentage")
SWAP_UTIL = Gauge("system_swap_utilization_percent", "Swap utilization percentage")
DISK_UTIL = Gauge("system_disk_utilization_percent", "Disk utilization percentage")
FRR_STATUS = Gauge("frr_status", "FRR status (1=running, 0=stopped)")
CHRONYD_STATUS = Gauge("chronyd_status", "Chronyd status (1=running, 0=stopped)")
CHRONYD_DRIFT = Gauge("chronyd_time_drift_seconds", "Chronyd time drift in seconds (Last offset)")
CHRONYD_STRATUM = Gauge("chronyd_stratum", "Chronyd/NTP stratum")

# BIND extra metrics
BIND_ZONE_COUNT = Gauge("bind_zone_count", "Number of zones currently loaded")
BIND_UPTIME = Gauge("bind_uptime_seconds", "BIND uptime in seconds")
BIND_QRY_AUTHORITATIVE = Gauge("bind_queries_authoritative_total", "Total authoritative queries from stats")
BIND_QRY_RECURSIVE = Gauge("bind_queries_recursive_total", "Total recursive queries from stats")

# NIC metrics
NIC_RX = Gauge("system_nic_rx_kbytes_per_sec", "NIC RX KB/s (psutil)")
NIC_TX = Gauge("system_nic_tx_kbytes_per_sec", "NIC TX KB/s (psutil)")

# BGP uptime metric
BGP_SESSION_UPTIME = Gauge("bgp_session_uptime_seconds", "BGP session uptime in seconds")

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
# BIND Stats
# =========================
def update_bind_stats():
    try:
        r = requests.get(BIND_STATS_URL, timeout=3)
        lines = r.text.splitlines()
        if len(lines) < 3:
            print("[bind-stats] Unexpected stats output format")
            return
        xml_text = lines[2].strip()
        root = ET.fromstring(xml_text)
        for elem in root.iter():
            if '}' in elem.tag:
                elem.tag = elem.tag.split('}', 1)[1]

        BIND_QUERIES_UDP.set(int(root.findtext(".//counter[@name='QryUDP']") or 0))
        BIND_QUERIES_TCP.set(int(root.findtext(".//counter[@name='QryTCP']") or 0))

        hits = int(root.findtext(".//counter[@name='CacheHits']") or 0)
        misses = int(root.findtext(".//counter[@name='CacheMisses']") or 0)
        ratio = hits / (hits + misses) if (hits + misses) > 0 else 0.0
        BIND_CACHE_HIT_RATIO.set(ratio)

        for counter in root.findall(".//counters[@type='qtype']//counter"):
            qtype = counter.attrib.get("name", "UNKNOWN")
            BIND_QUERIES_BY_TYPE.labels(qtype=qtype).set(int(counter.text or 0))

        for counter in root.findall(".//counters[@type='rcode']//counter"):
            rcode = counter.attrib.get("name", "UNKNOWN")
            BIND_RESPONSES_BY_CODE.labels(rcode=rcode).set(int(counter.text or 0))

        zones = root.findall(".//zones//zone")
        BIND_ZONE_COUNT.set(len(zones))
        for zone in zones:
            zone_name = zone.attrib.get("name", "")
            BIND_AXFR_SUCCESSES.labels(zone=zone_name).set(int(zone.findtext("axfr-success") or 0))
            BIND_AXFR_FAILURES.labels(zone=zone_name).set(int(zone.findtext("axfr-failure") or 0))
            BIND_SOA_REFRESH.labels(zone=zone_name).set(int(zone.findtext("refresh") or 0))
            BIND_SOA_EXPIRY.labels(zone=zone_name).set(int(zone.findtext("expiry") or 0))

        truncated_elem = root.find(".//counter[@name='Truncated']")
        BIND_TRUNCATED_TOTAL.set(int(truncated_elem.text) if truncated_elem is not None and truncated_elem.text else 0)

        BIND_QRY_AUTHORITATIVE.set(int(root.findtext(".//counter[@name='QryAuthoritative']") or 0))
        BIND_QRY_RECURSIVE.set(int(root.findtext(".//counter[@name='QryRecursive']") or 0))
        BIND_UPTIME.set(int(root.findtext(".//uptime") or 0))

    except Exception as e:
        print(f"[bind-stats] Error: {e}")

# =========================
# SERVFAIL Metrics
# =========================
SERVFAIL_REGEX = re.compile(
    r"(\d{1,2}-[A-Z][a-z]{2}-\d{4} \d{2}:\d{2}:\d{2}(?:\.\d+)?) .*query failed \(SERVFAIL\)",
    re.IGNORECASE
)
last_log_position = 0

def parse_bind_timestamp(date_str):
    for fmt in ("%d-%b-%Y %H:%M:%S.%f", "%d-%b-%Y %H:%M:%S"):
        try:
            return datetime.strptime(date_str, fmt).timestamp()
        except ValueError:
            continue
    return time.time()

def update_servfail_metrics():
    global last_log_position
    try:
        with open(LOG_PATH, "r") as f:
            f.seek(last_log_position)
            for line in f:
                match = SERVFAIL_REGEX.search(line)
                if match:
                    date_str = match.group(1)
                    ts = parse_bind_timestamp(date_str)
                    BIND_SERVFAIL_TOTAL.inc()
                    BIND_SERVFAIL_LAST.set(ts)
            last_log_position = f.tell()
    except FileNotFoundError:
        print(f"[servfail] Log file not found: {LOG_PATH}")
    except Exception as e:
        print(f"[servfail] Error parsing logs: {e}")

# =========================
# System & NIC Metrics
# =========================
def update_system_metrics():
    CPU_UTIL.set(psutil.cpu_percent())
    FRR_STATUS.set(1 if subprocess.call(["systemctl", "is-active", "--quiet", "frr"]) == 0 else 0)
    CHRONYD_STATUS.set(1 if subprocess.call(["systemctl", "is-active", "--quiet", "chronyd"]) == 0 else 0)
    try:
        result = subprocess.check_output(["chronyc", "tracking"], text=True, stderr=subprocess.STDOUT)
        drift = 0.0
        stratum = 0
        for line in result.splitlines():
            m = re.search(r"^Last offset\s*:\s*([+-]?\d+(?:\.\d+)?)\s+seconds", line.strip())
            if m:
                drift = float(m.group(1))
            m2 = re.search(r"^Stratum\s*:\s*(\d+)", line.strip())
            if m2:
                stratum = int(m2.group(1))
        CHRONYD_DRIFT.set(drift)
        CHRONYD_STRATUM.set(stratum)
    except Exception:
        CHRONYD_DRIFT.set(0.0)
        CHRONYD_STRATUM.set(0)

def update_memory_metrics():
    try:
        mem = psutil.virtual_memory()
        MEM_UTIL.set(mem.percent)
        swap = psutil.swap_memory()
        SWAP_UTIL.set(swap.percent)
    except Exception:
        MEM_UTIL.set(0.0)
        SWAP_UTIL.set(0.0)

def update_disk_metrics():
    try:
        usage = psutil.disk_usage(DISK_PATH)
        DISK_UTIL.set(usage.percent)
    except Exception:
        DISK_UTIL.set(0.0)

def update_nic_metrics_psutil():
    try:
        counters1 = psutil.net_io_counters(pernic=True)
        if IFACE_NAME not in counters1:
            print(f"[psutil] Interface {IFACE_NAME} not found")
            return
        time.sleep(1)
        counters2 = psutil.net_io_counters(pernic=True)
        if IFACE_NAME not in counters2:
            return
        rx_bytes = counters2[IFACE_NAME].bytes_recv - counters1[IFACE_NAME].bytes_recv
        tx_bytes = counters2[IFACE_NAME].bytes_sent - counters1[IFACE_NAME].bytes_sent
        NIC_RX.set(rx_bytes / 1024.0)
        NIC_TX.set(tx_bytes / 1024.0)
    except Exception as e:
        print(f"[psutil-nic] Error: {e}")

# =========================
# BGP Uptime
# =========================
def parse_bgp_uptime(uptime_str: str) -> int:
    total_seconds = 0
    if not uptime_str or uptime_str == "0":
        return 0
    match = re.match(r"(?:(\d+)w)?(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?", uptime_str)
    if not match:
        return 0
    weeks, days, hours, minutes, seconds = match.groups()
    if weeks:   total_seconds += int(weeks) * 7 * 24 * 3600
    if days:    total_seconds += int(days) * 24 * 3600
    if hours:   total_seconds += int(hours) * 3600
    if minutes: total_seconds += int(minutes) * 60
    if seconds: total_seconds += int(seconds)
    return total_seconds

def update_bgp_uptime():
    try:
        output = subprocess.check_output(
            'vtysh -c "show ip bgp sum" | sed -n "9p" | awk \'{print $9}\'',
            shell=True, text=True, stderr=subprocess.STDOUT
        ).strip()
        seconds = parse_bgp_uptime(output)
        BGP_SESSION_UPTIME.set(seconds)
    except Exception as e:
        print(f"[bgp-uptime] Error: {e}")
        BGP_SESSION_UPTIME.set(0)

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

        # Latency & accuracy
        if udp_result:
            BIND_LATENCY.set(udp_latency)
            accuracy = len(set(udp_result) & EXPECTED_IPS) / len(EXPECTED_IPS) * 100
        else:
            accuracy = 0
        BIND_RECORD_ACCURACY.set(accuracy)

        # Count failures
        if udp_result is None or udp_err:
            BIND_QUERY_FAILS.inc()
        if tcp_result is None or tcp_err:
            BIND_QUERY_FAILS.inc()

        # Count mismatches
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

        # DNSSEC errors
        if udp_err and "DNSSEC" in udp_err.upper():
            BIND_SECURITY_ERRORS.inc()

        update_system_metrics()
        update_memory_metrics()
        update_disk_metrics()
        update_nic_metrics_psutil()
        update_bind_stats()
        update_servfail_metrics()
        update_bgp_uptime()   # <-- new metric

        time.sleep(QUERY_INTERVAL)

if __name__ == "__main__":
    main()
