"""Asynchronous TCP port scanner."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Sequence

from .base import ScanResult, Scanner


@dataclass(slots=True)
class PortScanResult(ScanResult):
    """Result of a TCP port scan."""

    host: str
    open_ports: List[int] = field(default_factory=list)
    closed_ports: Dict[int, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


class PortScanner(Scanner[PortScanResult]):
    """Check if TCP ports are reachable on a host."""

    def __init__(
        self,
        host: str,
        ports: Sequence[int],
        *,
        timeout: float = 3.0,
        concurrency: int = 100,
    ) -> None:
        if not ports:
            raise ValueError("At least one port must be provided")
        if concurrency <= 0:
            raise ValueError("Concurrency must be greater than zero")

        self._host = host
        self._ports = list(dict.fromkeys(int(p) for p in ports))
        self._timeout = timeout
        self._concurrency = concurrency

    async def scan(self) -> PortScanResult:
        semaphore = asyncio.Semaphore(self._concurrency)
        open_ports: List[int] = []
        closed_ports: Dict[int, str] = {}

        async def check_port(port: int) -> None:
            try:
                async with semaphore:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(self._host, port),
                        timeout=self._timeout,
                    )
            except asyncio.TimeoutError:
                closed_ports[port] = "timeout"
            except OSError as exc:
                closed_ports[port] = exc.__class__.__name__
            else:
                open_ports.append(port)
                writer.close()
                try:
                    await writer.wait_closed()
                except ConnectionError:
                    pass

        start_time = time.perf_counter()
        await asyncio.gather(*(check_port(port) for port in self._ports))
        duration = time.perf_counter() - start_time

        return PortScanResult(
            host=self._host,
            open_ports=sorted(open_ports),
            closed_ports=dict(sorted(closed_ports.items())),
            duration=duration,
        )
