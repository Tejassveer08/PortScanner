# src/multi/scanner_thread.py
"""Thread-worker utilities for multithreaded port scanning (Python 3.8)."""

from typing import Tuple, List, Iterable, Callable
import socket
import contextlib
from concurrent.futures import ThreadPoolExecutor, as_completed

DEFAULT_TIMEOUT = 1.0

def is_port_open(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> bool:
    """Return True if a TCP connection to host:port succeeds."""
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
            return True
        except Exception:
            return False

def _scan_one(args: Tuple[str, int, float]) -> Tuple[int, bool]:
    host, port, timeout = args
    return (port, is_port_open(host, port, timeout))

def threaded_port_scan(host: str,
                       ports: Iterable[int],
                       timeout: float = DEFAULT_TIMEOUT,
                       max_workers: int = 50) -> List[Tuple[int, bool]]:
    """
    Scan ports concurrently on given host.
    Returns list of (port, is_open), order sorted by port.
    """
    ports = list(ports)
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_scan_one, (host, p, timeout)): p for p in ports}
        for fut in as_completed(futures):
            port, open_ = fut.result()
            results.append((port, open_))
    return sorted(results, key=lambda x: x[0])
