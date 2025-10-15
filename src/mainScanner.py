# src/mainScanner.py
"""Multithreaded port scanning CLI - Python 3.8"""

import argparse
from src.multi.scanner_thread import threaded_port_scan
from typing import List

def parse_ports(spec: str) -> List[int]:
    """Parse port specification strings like '22,80,443,1000-2000'"""
    out = set()
    for token in spec.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            a,b = token.split("-",1)
            out.update(range(int(a), int(b)+1))
        else:
            out.add(int(token))
    return sorted(out)

def main():
    parser = argparse.ArgumentParser(description="Multithreaded Port Scanner (py3)")
    parser.add_argument("host", help="Target host (ip or hostname)")
    parser.add_argument("--ports", "-p", default="1-1024",
                        help="Ports as comma-separated list and ranges e.g. 22,80,443,1000-2000")
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--workers", type=int, default=100, help="Number of concurrent threads")
    args = parser.parse_args()

    ports = parse_ports(args.ports)
    print(f"Scanning {args.host} on {len(ports)} ports with {args.workers} workers...")

    results = threaded_port_scan(args.host, ports, timeout=args.timeout, max_workers=args.workers)

    open_ports = [p for p, open_ in results if open_]
    for port, open_ in results:
        print(f"{port}: {'OPEN' if open_ else 'closed'}")

    print("\nSummary:")
    if open_ports:
        print(f"Open ports: {', '.join(str(p) for p in open_ports)}")
    else:
        print("No open ports found.")

if __name__ == "__main__":
    main()

