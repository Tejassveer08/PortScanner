# src/single/scanner.py
"""Single-threaded port scanner (Python 3.8)
Reference implementation: scans ports sequentially.
Used as fallback or for small scans.
"""

from typing import Iterable, List, Tuple
import socket
import contextlib

DEFAULT_TIMEOUT = 1.0  # seconds

def is_port_open(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> bool:
    """Return True if host:port accepts TCP connection."""
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
            return True
        except Exception:
            return False

def scan_ports(host: str, ports: Iterable[int], timeout: float = DEFAULT_TIMEOUT) -> List[Tuple[int, bool]]:
    results = []
    for p in ports:
        open_ = is_port_open(host, p, timeout=timeout)
        results.append((p, open_))
    return results

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Single-threaded port scanner (py3)")
    parser.add_argument("host", help="Target host (IP or hostname)")
    parser.add_argument("--ports", help="Comma-separated ports or range e.g. 20-25,80", default="1-1024")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    args = parser.parse_args()

    def parse_ports(s: str):
        out = []
        for part in s.split(","):
            if "-" in part:
                a,b = part.split("-",1)
                out.extend(range(int(a), int(b)+1))
            else:
                out.append(int(part))
        return out

    ports = parse_ports(args.ports)
    for port, open_ in scan_ports(args.host, ports, timeout=args.timeout):
        print(f"{port}: {'OPEN' if open_ else 'closed'}")

