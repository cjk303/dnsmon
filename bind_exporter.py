
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
DNS_TEST_RECORD = "P054ADSAMDC01.amer.EPIQCORP.COM"
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
    start_http_server(9119, addr="0.0.0.0")
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
        expected_ips = {"10.35.33.13"}  # Example.com known IP
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
ChatGPT said:
Got it 👍 I’ve looked through your Prometheus exporter script, here’s a breakdown and some recommendations:

✅ What it does well
Exports key metrics: service availability, query counts, failures, accuracy, latency, security failures, and comparison between direct vs BGP DNS.

Uses prometheus_client properly with gauges.

Performs health checks (TCP connect to port 53).

Handles errors gracefully (NXDOMAIN, Timeout, generic DNSException).

Latency measurement is correctly implemented.

Simple and self-contained: no external config files needed.

⚠️ Things to improve
Metric types

You're using Gauge for counters like bind_queries_total and bind_query_failures_total.
→ Prometheus best practice: use Counter for monotonically increasing values.
Example:

from prometheus_client import Counter
BIND_QUERIES = Counter('bind_queries_total', 'Total DNS queries')
BIND_QUERY_FAILS = Counter('bind_query_failures_total', 'Total DNS query failures')
BIND_SECURITY_ERRORS = Counter('bind_security_failures_total', 'DNSSEC or security validation failures')
Then replace .set() with .inc().

Hardcoded config

Test record, IPs, and expected IP are hardcoded.
→ Consider using environment variables or CLI args (argparse) so this exporter can be reused in other environments.

Record accuracy calculation

Currently compares only to one hardcoded IP ({"10.35.33.13"}).
→ If your record resolves to multiple IPs (round-robin DNS), this could cause false negatives.
Suggestion: load expected IPs from config or treat accuracy as percentage overlap between sets.

Latency metric

Only updates on successful queries.
→ Could be useful to export latency as NaN or 0 when queries fail, so you see the failure pattern in Grafana.

Direct vs BGP difference

Currently binary (0 or 1).
→ Maybe expose a percentage of overlap instead (like record accuracy), so you can detect partial mismatches.

Health check

Just checks TCP connect to port 53.
→ Doesn’t guarantee DNS is working. You already do queries anyway, so this check might be redundant.
Could simplify: mark bind_up as 1 if queries succeed.

Long-term counters

If the script restarts, counters reset.
→ That’s fine for simple exporters, but Prometheus best practice is to let Prometheus handle counter resets (they’re handled correctly in query functions like increase()).

🚀 Suggested Improvements
Switch counters (Gauge → Counter).

Make config flexible (env vars/CLI).

Export more granular error types:

BIND_QUERY_ERRORS = Counter('bind_query_errors_total', 'DNS query errors', ['error_type'])
Example labels: NXDOMAIN, TIMEOUT, SERVFAIL.

Add logging instead of print().

Optionally: expose per-server metrics with labels (server="direct" / server="bgp") instead of separate metrics.

👉 Do you want me to rewrite this exporter with improvements (counters, labeled metrics, env-configurable) so it’s production-ready?

You said:
add the following options Core DNS Service Metrics

Cache Hit Ratio (cache_hits / (cache_hits + cache_misses)):
Shows how effective your resolver is. Low hit rate might mean misconfiguration or high churn.

Zone Transfer Activity: track AXFR/IXFR success/fail counts.
Useful if you’re running authoritative servers with slaves/secondaries.

Zone Expiry / Refresh Issues: monitor SOA refresh, retry, and expiry timers to catch stale zones.

🔹 Traffic Patterns

Top Clients (by query volume): detect misbehaving apps or abuse.

Query Types Breakdown: A, AAAA, MX, TXT, PTR, SRV, etc. (helps detect scanning or attacks).

Recursion Requested vs Non-Recursive: see if you’re getting unusual recursion requests.

NXDOMAIN Rate: high NXDOMAIN responses may indicate misconfigurations, typo traffic, or DDoS attempts.

🔹 Performance & Reliability

Response Size Distribution: small vs large answers (DNSSEC can cause large responses).

TCP vs UDP Queries: should mostly be UDP; high TCP % can indicate problems.

Dropped/Timeout Queries: detect network or firewall issues.

EDNS Compliance: track queries with/without EDNS and failures.

🔹 Security / Abuse Detection

QPS Thresholds per client: spot DDoS or amplification attempts.

Blocked Queries (if using RPZ or ACLs).

DNSSEC Validation Failures: important if resolver validates signatures.

Unexpected Query Origins: queries from outside your intended client networks.

🔹 System Integration

BIND process memory usage / CPU load (via node_exporter).

File descriptor usage (too many open sockets can cause failures).

Log-based Metrics (via something like promtail → Loki → Grafana):

SERVFAIL reasons

Configuration reloads

Zone load errors
ChatGPT said:
Perfect 👍 you’re thinking about building this into a real observability-grade exporter, not just a health probe. Let’s break it down carefully, because many of the new metrics you listed require different data sources than the current simple DNS-query approach.

🛠 Where These Metrics Come From
1. Core DNS Service Metrics
Cache Hit Ratio → Requires stats from BIND (rndc stats) or parsing its statistics channel XML (port 8053). Your current exporter does not have access to cache internals.

Zone Transfer Activity (AXFR/IXFR) → Needs BIND logs or statistics XML.

Zone Expiry / Refresh Issues → Only available from zone/soa monitoring or rndc dumpdb/XML stats.

➡️ These require parsing BIND’s statistics channel or logs, not just resolver queries.

2. Traffic Patterns
Top Clients, Query Types Breakdown, Recursion, NXDOMAIN rate → Available from BIND XML stats, or log parsing.

You could also approximate NXDOMAIN from your current query_dns() wrapper, but it won’t capture global traffic.

3. Performance & Reliability
Response size distribution, TCP vs UDP, EDNS compliance, Dropped queries → Again, only in statistics XML or logs.

Your current exporter only runs a single test query → not enough for these metrics.

4. Security / Abuse Detection
QPS thresholds, blocked queries, DNSSEC validation failures, unexpected origins → Need either:

BIND query logs

RPZ log events

or statistics XML

5. System Integration
Process memory / CPU / FDs → Already covered by node_exporter (no need to reinvent).

Log-based metrics → Better via promtail → Loki → Grafana, not inside your Python exporter.

🔑 Recommendation for Integration
Instead of stuffing all of this into the Python probe, I suggest two data sources:

Current lightweight probe (what you wrote)

Health check

Accuracy / consistency (direct vs BGP)

Latency

Query success/failure

BIND statistics channel parser (new module)

Access BIND’s XML stats (http://127.0.0.1:8053/)

Parse and expose metrics like cache hits, misses, NXDOMAIN, recursion, etc.

This is how the existing bind_exporter works.

🚀 Example: Adding Cache Hit Ratio
If you enable BIND statistics channel in named.conf:

statistics-channels {
    inet 127.0.0.1 port 8053 allow { 127.0.0.1; };
};
Then add code to fetch and parse XML:

import requests
import xml.etree.ElementTree as ET
from prometheus_client import Gauge

BIND_CACHE_HIT_RATIO = Gauge('bind_cache_hit_ratio', 'Cache hit ratio')

def update_cache_stats():
    try:
        r = requests.get("http://127.0.0.1:8053/", timeout=2)
        root = ET.fromstring(r.text)

        hits = int(root.findtext(".//caches//hits"))
        misses = int(root.findtext(".//caches//misses"))
        ratio = hits / (hits + misses) if (hits + misses) > 0 else 0

        BIND_CACHE_HIT_RATIO.set(ratio)
    except Exception as e:
        print(f"Failed to get cache stats: {e}")
📊 Strategy Going Forward
Keep this exporter focused on probe-style metrics (latency, correctness, BGP vs direct).

Add a BIND stats parser module to export:

Cache hit ratio

NXDOMAIN counts

Query type breakdown

TCP/UDP ratio

For system & log-based metrics, rely on:

node_exporter

promtail → Loki

👉 Do you want me to extend your script with a statistics-channel parser for some of these (cache hit ratio, NXDOMAIN rate, query type breakdown, TCP/UDP split)? That’s the cleanest next step.

You said:
the bind statistics channel is allowed
ChatGPT said:
Perfect ✅ — if the BIND statistics channel is enabled, then you can get most of the advanced metrics you listed without scraping logs or hacking queries.

Let’s make this concrete:

🔑 What We Can Pull From the Stats Channel (XML/JSON depending on BIND version)
From http://127.0.0.1:8053/ (or whatever IP/port you configured):

Cache Metrics

cache_hits, cache_misses → compute cache hit ratio.

Query Counters

By opcode (QUERY, NOTIFY, UPDATE, AXFR, IXFR).

By qtype (A, AAAA, MX, TXT, …).

Return Codes

NOERROR, NXDOMAIN, SERVFAIL, etc.

Transport

TCP vs UDP query counts.

Security

DNSSEC validation failures, EDNS compliance.

Zone Transfer

IXFR/AXFR stats under "zones".

SOA timers

Refresh, retry, expiry (to monitor stale zones).

🔨 How to Integrate Into Your Exporter
Keep your current active query probe (latency, correctness, BGP vs direct).

Add a new function to fetch & parse BIND statistics.

Expose metrics via Prometheus gauges & counters.

🧩 Example: Parsing Cache + Query Types
import requests
import xml.etree.ElementTree as ET
from prometheus_client import Gauge, Counter

# New Metrics
BIND_CACHE_HIT_RATIO = Gauge("bind_cache_hit_ratio", "DNS cache hit ratio")
BIND_QUERIES_BY_TYPE = Counter("bind_queries_by_type_total", "DNS queries by type", ["qtype"])
BIND_QUERIES_BY_TRANSPORT = Counter("bind_queries_by_transport_total", "DNS queries by transport", ["transport"])
BIND_RESPONSES_BY_CODE = Counter("bind_responses_by_rcode_total", "DNS responses by return code", ["rcode"])

def update_bind_stats():
    try:
        r = requests.get("http://127.0.0.1:8053/", timeout=3)
        root = ET.fromstring(r.text)

        # Cache stats
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
            transport = counter.attrib.get("name")  # udp/tcp
            value = int(counter.text)
            BIND_QUERIES_BY_TRANSPORT.labels(transport=transport).inc(value)

        # RCODEs
        for counter in root.findall(".//counters[@type='rcode']//counter"):
            rcode = counter.attrib.get("name")  # NOERROR, NXDOMAIN, SERVFAIL...
            value = int(counter.text)
            BIND_RESPONSES_BY_CODE.labels(rcode=rcode).inc(value)

    except Exception as e:
        print(f"Error fetching BIND stats: {e}")
⚠️ Important Notes
Use Counters (with .inc()) for query counts, NXDOMAINs, etc.

Use Gauges for ratios, current SOA timers, memory usage.

The XML schema differs slightly between BIND 9.10 / 9.11 / 9.16+, so you may need to adjust XPath queries depending on your version.

Stats are cumulative since BIND start → Prometheus handles resets automatically.

🚀 Next Step
I can merge this parser into your existing exporter so it:

Runs your active test loop (latency, correctness).

Periodically (e.g. every 30s) scrapes the stats channel.

Exposes both sets of metrics on the same /metrics endpoint.

👉 Do you want me to rewrite your script so it integrates the stats channel parsing (cache ratio, query type breakdown, NXDOMAIN, TCP vs UDP, etc.) alongside your current active checks?

You said:
yes
ChatGPT said:
Great 🚀 Let’s merge your active query probe with a statistics channel parser so you get both views:

Probe-based metrics → latency, correctness, direct vs BGP consistency

Stats-based metrics → cache efficiency, query breakdowns, NXDOMAIN rate, transport usage, etc.

Here’s a rewritten version of your exporter:

✅ Done — I’ve merged your active probe loop with a BIND statistics channel parser.
This version now exports:

Health, latency, failures, accuracy, BGP vs direct (your original probe)

Cache hit ratio, queries by type, queries by transport, responses by code (stats channel)

Would you like me to also add zone transfer activity (AXFR/IXFR success/fails) and SOA timers (refresh/expiry) from the stats channel?

You said:
yes
ChatGPT said:
I’ve added parsing of the BIND statistics channel for:

AXFR/IXFR success/failure per zone

SOA refresh and expiry timers per zone

These metrics now integrate alongside your existing probe metrics.

You said:
can you also add multiple test urls
ChatGPT said:
I've updated the script to allow multiple DNS test records. The exporter will now loop through each record in DNS_TEST_RECORDS and perform the probes for all of them.

You said:
roll back to the previous version
ChatGPT said:
Rolled back the script to its previous version, restoring the single test record and removing the extended statistics-channel and multiple test URLs.

You said:
give me the updated version just without the multiple url
ChatGPT said:

Answer in chat instead
The script has been restored to the version with a single test URL, keeping all the original metrics and logic intact.



No file chosenNo file chosen
ChatGPT can make mistakes. Check important info. See Cookie Preferences.


Bind Exporter
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
43
44
45
46
47
48
49
50
51
52
53
54
55
56
57
58
59
60
61
62
63
64
65
66
67
68
69
70
71
72
73
74
75
76
77
78
79
80
81
82
83
84
#!/usr/bin/env python3
import time
import socket
import dns.resolver
import dns.exception
import requests
import xml.etree.ElementTree as ET
from prometheus_client import start_http_server, Gauge, Counter

# -----------------------------
# Probe-based Metrics (active)
# -----------------------------
BIND_UP = Gauge('bind_up', 'BIND service status (1=up, 0=down)')
BIND_QUERIES = Counter('bind_queries_total', 'Total DNS queries')
BIND_QUERY_FAILS = Counter('bind_query_failures_total', 'Total DNS query failures')
BIND_RECORD_ACCURACY = Gauge('bind_record_accuracy', 'Accuracy of DNS records (percentage)')
BIND_LATENCY = Gauge('bind_latency_seconds', 'DNS query latency in seconds')
BIND_SECURITY_ERRORS = Counter('bind_security_failures_total', 'DNSSEC or security validation failures')
BIND_DIRECT_VS_BGP = Gauge('bind_direct_vs_bgp_difference', 'Difference between direct and BGP VIP query results')

# -----------------------------
# Statistics-channel Metrics
# -----------------------------
BIND_CACHE_HIT_RATIO = Gauge("bind_cache_hit_ratio", "DNS cache hit ratio")
BIND_QUERIES_BY_TYPE = Counter("bind_queries_by_type_total", "DNS queries by type", ["qtype"])
BIND_QUERIES_BY_TRANSPORT = Counter("bind_queries_by_transport_total", "DNS queries by transport", ["transport"])
BIND_RESPONSES_BY_CODE = Counter("bind_responses_by_rcode_total", "DNS responses by return code", ["rcode"])
BIND_AXFR_SUCCESSES = Counter("bind_axfr_success_total", "AXFR zone transfer successes", ["zone"])
BIND_AXFR_FAILURES = Counter("bind_axfr_failure_total", "AXFR zone transfer failures", ["zone"])
BIND_SOA_REFRESH = Gauge("bind_soa_refresh_seconds", "SOA refresh timer for zones", ["zone"])
BIND_SOA_EXPIRY = Gauge("bind_soa_expiry_seconds", "SOA expiry timer for zones", ["zone"])

# -----------------------------
# Config
# -----------------------------
DNS_TEST_RECORD = "P054ADSAMDC01.amer.EPIQCORP.COM"
DNS_TEST_TYPE = "A"
DIRECT_DNS = "127.0.0.1"
BGP_DNS = "10.255.0.10"
QUERY_INTERVAL = 10   # probe loop interval
STATS_INTERVAL = 30   # stats scrape interval
BIND_STATS_URL = "http://127.0.0.1:8053/"  # adjust if different


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
    """Fetch and parse BIND statistics channel (XML)."""
    try:
        r = requests.get(BIND_STATS_URL, timeout=3)
        root = ET.fromstring(r.text)

        # Cache stats
        hits = int(root.findtext(".//counters[@type='cache']//counter[@name='hits']", default="0"))
        misses = int(root.findtext(".//counters[@type='cache']//counter[@name='misses']", default="0"))
        ratio = hits / (hits + misses) if (hits + misses) > 0 else 0
        BIND_CACHE_HIT_RATIO.set(ratio)

        # Query types
You are viewing a previous version
Restore this version to make edits

Restore this version

Back to latest version
