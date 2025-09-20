#!/usr/bin/env python3
import subprocess
import re

def parse_bgp_uptime(uptime_str: str) -> int:
    """Convert BGP uptime string like '01w3d08h' to seconds."""
    total = 0
    try:
        m = re.search(r'(\d+)w', uptime_str)
        if m: total += int(m.group(1)) * 7 * 24 * 3600
        m = re.search(r'(\d+)d', uptime_str)
        if m: total += int(m.group(1)) * 24 * 3600
        m = re.search(r'(\d+)h', uptime_str)
        if m: total += int(m.group(1)) * 3600
        m = re.search(r'(\d+)m', uptime_str)
        if m: total += int(m.group(1)) * 60
        if ':' in uptime_str:  # fallback HH:MM:SS
            parts = uptime_str.split(':')
            if len(parts) == 3:
                h, mi, s = map(int, parts)
                total += h*3600 + mi*60 + s
            elif len(parts) == 2:
                mi, s = map(int, parts)
                total += mi*60 + s
    except Exception:
        pass
    return total

def get_bgp_uptime():
    try:
        output = subprocess.check_output(
            ["vtysh", "-c", "show ip bgp sum"],
            text=True,
            stderr=subprocess.STDOUT
        ).splitlines()

        print("Raw vtysh output:")
        for i, line in enumerate(output):
            print(f"{i+1}: {line}")

        # Try to find uptime column (usually 9th column with w/d/h format)
        for line in output:
            fields = line.split()
            if len(fields) > 8 and re.search(r'\d+[wdh:]', fields[8]):
                uptime_str = fields[8]
                seconds = parse_bgp_uptime(uptime_str)
                minutes = seconds / 60
                print(f"BGP uptime: {uptime_str} -> {seconds} seconds -> {minutes:.2f} minutes")
                return seconds
        print("No BGP uptime found.")
        return 0

    except Exception as e:
        print(f"Error getting BGP uptime: {e}")
        return 0

if __name__ == "__main__":
    get_bgp_uptime()
