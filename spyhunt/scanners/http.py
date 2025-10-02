"""HTTP reconnaissance scanner."""

from __future__ import annotations

import asyncio
import ssl
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, Iterable, List, Optional

import aiohttp

from .base import ScanError, ScanResult, Scanner


@dataclass(slots=True)
class HttpScanResult(ScanResult):
    """Structured data about an HTTP endpoint."""

    url: str
    status: Optional[int]
    headers: Dict[str, str]
    redirects: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


class HttpScanner(Scanner[HttpScanResult]):
    """Collect status information and lightweight fingerprinting for an URL."""

    def __init__(
        self,
        url: str,
        *,
        timeout: float = 10.0,
        follow_redirects: bool = True,
        verify_ssl: bool = True,
        user_agent: str = "spyhunt/4.1",
        technology_hints: Optional[Iterable[str]] = None,
    ) -> None:
        if not url.startswith(("http://", "https://")):
            raise ValueError("URL must include scheme (http or https)")

        self._url = url
        self._timeout = timeout
        self._follow_redirects = follow_redirects
        self._verify_ssl = verify_ssl
        self._user_agent = user_agent
        self._technology_hints = [hint.lower() for hint in technology_hints or []]

    async def scan(self) -> HttpScanResult:
        timeout = aiohttp.ClientTimeout(total=self._timeout)
        ssl_context = None
        if not self._verify_ssl:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        connector = aiohttp.TCPConnector(ssl=ssl_context)

        start_time = time.perf_counter()
        try:
            async with aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
                headers={"User-Agent": self._user_agent},
            ) as session:
                async with session.get(
                    self._url, allow_redirects=self._follow_redirects
                ) as response:
                    body = await self._safe_read_body(response)
                    technologies = self._detect_technologies(response.headers, body)
                    if self._technology_hints:
                        for hint in self._technology_hints:
                            if hint not in technologies:
                                technologies.append(hint)

                    duration = time.perf_counter() - start_time
                    return HttpScanResult(
                        url=str(response.url),
                        status=response.status,
                        headers={k: v for k, v in response.headers.items()},
                        redirects=[str(history.url) for history in response.history],
                        technologies=sorted(technologies),
                        duration=duration,
                    )
        except asyncio.TimeoutError as exc:
            duration = time.perf_counter() - start_time
            raise ScanError(f"Timeout after {self._timeout:.1f}s (took {duration:.2f}s)") from exc
        except aiohttp.ClientError as exc:
            duration = time.perf_counter() - start_time
            raise ScanError(f"HTTP request failed after {duration:.2f}s: {exc}") from exc

    async def _safe_read_body(self, response: aiohttp.ClientResponse) -> str:
        try:
            body = await response.text(errors="ignore")
        except UnicodeDecodeError:
            return ""
        except aiohttp.ClientError:
            return ""
        return body[:100_000]

    def _detect_technologies(self, headers: aiohttp.typedefs.LooseHeaders, body: str) -> List[str]:
        technologies: List[str] = []
        seen: set[str] = set()

        def add(value: str) -> None:
            key = value.lower()
            if key not in seen:
                technologies.append(value)
                seen.add(key)

        header_map = {k.lower(): v for k, v in headers.items()}  # type: ignore[arg-type]

        server_header = header_map.get("server")
        if server_header:
            add(server_header.split()[0])

        powered_by = header_map.get("x-powered-by")
        if powered_by:
            add(powered_by)

        lowered_body = body.lower()
        if "wordpress" in lowered_body:
            add("WordPress")
        if "drupal.settings" in body:
            add("Drupal")
        if "django" in lowered_body:
            add("Django")

        return technologies
