#!/usr/bin/env python3
import time
import socket
import dns.resolver
import dns.exception
from prometheus_client import start_http_server, Gauge

# Prometheus Gauges
BIND_UP = Gauge('bind_up', 'BIND service status (1=up, 0=down)')
BIND_QUERIES = Gauge('bind_queries_total', 'Total DNS queries')
BIND_QUERY_FAILS = Gauge('bind_query_failures_total', 'Total DNS query failures')
BIND_RECORD_ACCURACY = Gauge('bind_record_accuracy', 'Accuracy of DNS records (percentage)')
BIND_LATENCY = Gauge('bind_latency_seconds', 'DNS query latency in seconds')
BIND_SECURITY_ERRORS = Gauge('bind_security_failures_total', 'DNSSEC or security validation failures')
BIND_DIRECT_VS_BGP = Gauge('bind_direct_vs_bgp_difference', 'Difference between direct and BGP VIP query results')

# Config
DNS_TEST_RECORD = "example.com"
DNS_TEST_TYPE = "A"
DIRECT_DNS = "127.0.0.1"
BGP_DNS = "10.255.0.10"
QUERY_INTERVAL = 10  # seconds


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
        # Try connecting to port 53 TCP
        sock = socket.create_connection((DIRECT_DNS, 53), timeout=2)
        sock.close()
        return True
    except OSError:
        return False


def main():
    # Start HTTP server for Prometheus to scrape
    start_http_server(9119)
    print("BIND exporter started on :9119")

    total_queries = 0
    total_failures = 0
    total_security_failures = 0

    while True:
        # Check BIND health
        if check_bind_health():
            BIND_UP.set(1)
        else:
            BIND_UP.set(0)

        # Direct query
        direct_result, direct_latency, direct_err = query_dns(DIRECT_DNS, DNS_TEST_RECORD, DNS_TEST_TYPE)

        # BGP VIP query
        bgp_result, bgp_latency, bgp_err = query_dns(BGP_DNS, DNS_TEST_RECORD, DNS_TEST_TYPE)

        # Metrics update
        if direct_result is not None:
            total_queries += 1
            BIND_LATENCY.set(direct_latency)
        else:
            total_failures += 1

        # Security metrics (simulate by checking if DNSSEC failure keyword appears)
        if direct_err and "DNSSEC" in direct_err.upper():
            total_security_failures += 1

        # Record accuracy (compare result to expected)
        expected_ips = {"93.184.216.34"}  # Example.com known IP
        if direct_result:
            accuracy = len(set(direct_result) & expected_ips) / len(expected_ips) * 100
        else:
            accuracy = 0
        BIND_RECORD_ACCURACY.set(accuracy)

        # Comparison between direct and BGP VIP
        if direct_result and bgp_result:
            diff = 0 if set(direct_result) == set(bgp_result) else 1
        else:
            diff = 1
        BIND_DIRECT_VS_BGP.set(diff)

        # Update counters
        BIND_QUERIES.set(total_queries)
        BIND_QUERY_FAILS.set(total_failures)
        BIND_SECURITY_ERRORS.set(total_security_failures)

        time.sleep(QUERY_INTERVAL)


if __name__ == "__main__":
    main()
