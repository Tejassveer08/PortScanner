# src/ipscanner/__init__.py
"""IP Scanner package for Python 3.8"""
from .ipscanner import expand_cidr, expand_range, scan_hosts_parallel
__all__ = ["expand_cidr", "expand_range", "scan_hosts_parallel"]
