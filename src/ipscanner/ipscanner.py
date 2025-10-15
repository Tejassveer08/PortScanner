# src/ipscanner/ipscanner.py
"""
Utilities to expand IP ranges/CIDR notation and scan hosts in parallel.
Note: This does NOT use raw ICMP; it uses TCP connection attempts to a probe port
(e.g., 80 or 443) to heuristically detect live hosts without sudo privileges.
"""

from typing import List, Iterable, Tuple
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import contextlib

DEFAULT_PROBE_PORT = 80
DEFAULT_TIMEOUT = 0.6

def expand_cidr(cidr: str) -> List[str]:
    """Return list of IP strings for a CIDR block (excluding network and broadcast for IPv4 if desired)."""
    net = ipaddress.ip_network(cidr, strict=False)
    return [str(ip) for ip in net.hosts()]

def expand_range(range_spec: str) -> List[str]:
    """
    Expand a range like '192.168.1.1-192.168.1.10' into list of IPs.
    Or single IP string returns [ip].
    """
    if "-" in range_spec:
        start_s, end_s = range_spec.split("-", 1)
        start = ipaddress.ip_address(start_s.strip())
        end = ipaddress.ip_address(end_s.strip())
        if start > end:
            start, end = end, start
        out = []
        cur = int(start)
        while cur <= int(end):
            out.append(str(ipaddress.ip_address(cur)))
            cur += 1
        return out
    else:
        # Single address
        return [str(ipaddress.ip_address(range_spec.strip()))]

def _probe_host(host: str, port: int = DEFAULT_PROBE_PORT, timeout: float = DEFAULT_TIMEOUT) -> Tuple[str, bool]:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
            return (host, True)
        except Exception:
            return (host, False)

def scan_hosts_parallel(hosts: Iterable[str],
                        probe_port: int = DEFAULT_PROBE_PORT,
                        timeout: float = DEFAULT_TIMEOUT,
                        max_workers: int = 100) -> List[Tuple[str, bool]]:
    """Return list of tuples (host, up_bool)."""
    hosts = list(hosts)
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_probe_host, h, probe_port, timeout): h for h in hosts}
        for fut in as_completed(futures):
            results.append(fut.result())
    return sorted(results, key=lambda x: x[0])
