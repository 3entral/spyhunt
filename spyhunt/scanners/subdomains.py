"""DNS-based subdomain discovery scanner."""

from __future__ import annotations

import asyncio
import socket
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Sequence

from .base import ScanResult, Scanner

# A small but representative set of prefixes that frequently appear in front of
# production domains.  The list is intentionally short so that default scans
# remain fast while still covering common services.
DEFAULT_SUBDOMAIN_PREFIXES: tuple[str, ...] = (
    "www",
    "mail",
    "api",
    "dev",
    "staging",
    "beta",
    "admin",
    "portal",
    "vpn",
    "cdn",
    "assets",
    "static",
    "img",
    "blog",
    "support",
    "docs",
    "status",
    "shop",
    "m",
)


@dataclass(slots=True)
class ResolvedSubdomain:
    """A successfully resolved subdomain and its address records."""

    hostname: str
    addresses: List[str]

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


@dataclass(slots=True)
class SubdomainScanResult(ScanResult):
    """Results collected from the :class:`SubdomainScanner`."""

    domain: str
    resolved: List[ResolvedSubdomain] = field(default_factory=list)
    unresolved: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {
            "domain": self.domain,
            "duration": self.duration,
            "resolved": [entry.to_dict() for entry in self.resolved],
            "unresolved": dict(self.unresolved),
        }


class SubdomainScanner(Scanner[SubdomainScanResult]):
    """Enumerate common subdomains for a given domain via DNS lookups."""

    def __init__(
        self,
        domain: str,
        candidates: Sequence[str] | None = None,
        *,
        include_root: bool = False,
        timeout: float = 2.0,
        concurrency: int = 50,
    ) -> None:
        domain = domain.strip().lower().strip(".")
        if not domain:
            raise ValueError("Domain must not be empty")
        if concurrency <= 0:
            raise ValueError("Concurrency must be greater than zero")
        if timeout <= 0:
            raise ValueError("Timeout must be greater than zero")

        labels: List[str] = []
        seen: set[str] = set()

        if include_root:
            labels.append("")
            seen.add("")

        for label in candidates or DEFAULT_SUBDOMAIN_PREFIXES:
            label = label.strip().lower()
            if not label or label in seen:
                continue
            labels.append(label)
            seen.add(label)

        if not labels:
            raise ValueError("No subdomain candidates were provided")

        self._domain = domain
        self._labels = labels
        self._timeout = timeout
        self._concurrency = concurrency

    async def scan(self) -> SubdomainScanResult:
        semaphore = asyncio.Semaphore(self._concurrency)
        resolved: List[ResolvedSubdomain] = []
        unresolved: Dict[str, str] = {}

        loop = asyncio.get_running_loop()

        async def resolve(label: str) -> None:
            hostname = self._domain if not label else f"{label}.{self._domain}"
            async with semaphore:
                try:
                    infos = await asyncio.wait_for(
                        loop.getaddrinfo(
                            hostname,
                            None,
                            family=socket.AF_UNSPEC,
                            type=socket.SOCK_STREAM,
                        ),
                        timeout=self._timeout,
                    )
                except asyncio.TimeoutError:
                    unresolved[hostname] = "timeout"
                except socket.gaierror as exc:
                    message = exc.strerror or (exc.args[1] if len(exc.args) > 1 else str(exc))
                    unresolved[hostname] = message or "not found"
                except OSError as exc:
                    unresolved[hostname] = exc.strerror or str(exc)
                else:
                    addresses = sorted(
                        {
                            info[4][0]
                            for info in infos
                            if info and len(info) >= 5 and info[4]
                        }
                    )
                    if addresses:
                        resolved.append(
                            ResolvedSubdomain(hostname=hostname, addresses=addresses)
                        )
                    else:
                        unresolved[hostname] = "no address records"

        start_time = time.perf_counter()
        await asyncio.gather(*(resolve(label) for label in self._labels))
        duration = time.perf_counter() - start_time

        resolved.sort(key=lambda entry: entry.hostname)
        ordered_unresolved = dict(sorted(unresolved.items()))

        return SubdomainScanResult(
            domain=self._domain,
            resolved=resolved,
            unresolved=ordered_unresolved,
            duration=duration,
        )


__all__ = [
    "DEFAULT_SUBDOMAIN_PREFIXES",
    "ResolvedSubdomain",
    "SubdomainScanResult",
    "SubdomainScanner",
]
