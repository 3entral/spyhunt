"""Command line entry point for the modernised Spyhunt toolkit."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import List, Sequence

from .scanners import (
    HttpScanResult,
    HttpScanner,
    PortScanResult,
    PortScanner,
    SubdomainScanResult,
    SubdomainScanner,
)
from .scanners.base import ScanError


def parse_ports(value: str) -> List[int]:
    """Convert comma separated port expressions to a sorted list of integers."""

    if not value:
        raise argparse.ArgumentTypeError("port specification must not be empty")

    ports: set[int] = set()
    for chunk in value.split(","):
        chunk = chunk.strip()
        if not chunk:
            raise argparse.ArgumentTypeError("empty port entry is not allowed")
        if "-" in chunk:
            start_str, end_str = chunk.split("-", 1)
            try:
                start = int(start_str)
                end = int(end_str)
            except ValueError as exc:
                raise argparse.ArgumentTypeError(
                    f"invalid port range '{chunk}'"
                ) from exc
            if start > end:
                raise argparse.ArgumentTypeError(
                    f"invalid port range '{chunk}' (start > end)"
                )
            for port in range(start, end + 1):
                _validate_port(port)
                ports.add(port)
        else:
            try:
                port = int(chunk)
            except ValueError as exc:
                raise argparse.ArgumentTypeError(
                    f"invalid port '{chunk}'"
                ) from exc
            _validate_port(port)
            ports.add(port)

    if not ports:
        raise argparse.ArgumentTypeError("no ports were parsed")

    return sorted(ports)


def _validate_port(port: int) -> None:
    if not 0 < port <= 65535:
        raise argparse.ArgumentTypeError(
            f"port {port} is outside the valid range (1-65535)"
        )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="spyhunt",
        description=(
            "Lightweight reconnaissance helpers refactored from the legacy Spyhunt tool."
        ),
    )
    parser.add_argument(
        "--format",
        choices={"json", "text"},
        default="json",
        help="Output format (default: json).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional file to write the scan results to (JSON is always used).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable informational log messages.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable verbose debug logging.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    http_parser = subparsers.add_parser(
        "http",
        help="Inspect an HTTP or HTTPS endpoint.",
    )
    http_parser.add_argument("url", help="Target URL, including http:// or https://")
    http_parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Request timeout in seconds (default: 10).",
    )
    http_parser.add_argument(
        "--no-redirects",
        action="store_true",
        help="Disable following redirects.",
    )
    http_parser.add_argument(
        "--insecure",
        action="store_true",
        help="Do not validate TLS certificates.",
    )
    http_parser.add_argument(
        "--user-agent",
        default="spyhunt/4.1",
        help="User-Agent header to use for the request.",
    )
    http_parser.add_argument(
        "--hint",
        action="append",
        default=[],
        metavar="TECH",
        help="Optional technology hints to include in the result.",
    )

    port_parser = subparsers.add_parser(
        "ports",
        help="Scan TCP ports on a host.",
    )
    port_parser.add_argument("host", help="Target host name or IP address.")
    port_parser.add_argument(
        "--ports",
        type=parse_ports,
        default=parse_ports("80,443"),
        help="Comma separated port list or ranges (e.g. 80,443,1000-1010).",
    )
    port_parser.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="Connection timeout for each port (default: 3).",
    )
    port_parser.add_argument(
        "--concurrency",
        type=int,
        default=100,
        help="Maximum concurrent connection attempts (default: 100).",
    )

    subdomain_parser = subparsers.add_parser(
        "subdomains",
        help="Enumerate common subdomains via DNS lookups.",
    )
    subdomain_parser.add_argument("domain", help="Base domain (e.g. example.com).")
    subdomain_parser.add_argument(
        "--wordlist",
        type=Path,
        help="Optional file with subdomain prefixes (one per line).",
    )
    subdomain_parser.add_argument(
        "--include-root",
        action="store_true",
        help="Include the bare domain in the scan results.",
    )
    subdomain_parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="Resolution timeout per candidate in seconds (default: 2).",
    )
    subdomain_parser.add_argument(
        "--concurrency",
        type=int,
        default=50,
        help="Number of in-flight DNS queries (default: 50).",
    )

    return parser


async def _run_http(args: argparse.Namespace) -> HttpScanResult:
    scanner = HttpScanner(
        args.url,
        timeout=args.timeout,
        follow_redirects=not args.no_redirects,
        verify_ssl=not args.insecure,
        user_agent=args.user_agent,
        technology_hints=args.hint,
    )
    return await scanner.scan()


async def _run_ports(args: argparse.Namespace) -> PortScanResult:
    scanner = PortScanner(
        args.host,
        args.ports,
        timeout=args.timeout,
        concurrency=args.concurrency,
    )
    return await scanner.scan()


def _load_wordlist(path: Path) -> List[str]:
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ScanError(f"Failed to read wordlist {path}: {exc}") from exc

    entries = [
        line.strip()
        for line in content.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not entries:
        raise ScanError(f"Wordlist {path} did not contain any entries")
    return entries


async def _run_subdomains(args: argparse.Namespace) -> SubdomainScanResult:
    candidates = _load_wordlist(args.wordlist) if args.wordlist else None
    scanner = SubdomainScanner(
        args.domain,
        candidates=candidates,
        include_root=args.include_root,
        timeout=args.timeout,
        concurrency=args.concurrency,
    )
    return await scanner.scan()


async def _dispatch(args: argparse.Namespace) -> object:
    if args.command == "http":
        return await _run_http(args)
    if args.command == "ports":
        return await _run_ports(args)
    if args.command == "subdomains":
        return await _run_subdomains(args)
    raise RuntimeError(f"Unsupported command: {args.command}")


def _configure_logging(args: argparse.Namespace) -> None:
    if args.debug:
        level = logging.DEBUG
    elif args.verbose:
        level = logging.INFO
    else:
        level = logging.WARNING
    logging.basicConfig(level=level, format="[%(levelname)s] %(message)s")


def _format_result(result: object, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(_result_to_dict(result), indent=2, sort_keys=True)
    return _format_text(result)


def _result_to_dict(result: object) -> dict:
    if isinstance(result, (HttpScanResult, PortScanResult, SubdomainScanResult)):
        return result.to_dict()
    raise TypeError(f"Unsupported result object: {result!r}")


def _format_text(result: object) -> str:
    if isinstance(result, HttpScanResult):
        lines = [
            f"URL: {result.url}",
            f"Status: {result.status if result.status is not None else 'error'}",
            f"Duration: {result.duration:.2f}s",
        ]
        if result.technologies:
            lines.append("Technologies: " + ", ".join(result.technologies))
        if result.redirects:
            lines.append("Redirects:")
            lines.extend(f"  - {redirect}" for redirect in result.redirects)
        if result.headers:
            lines.append("Headers:")
            for key, value in sorted(result.headers.items()):
                lines.append(f"  {key}: {value}")
        if result.error:
            lines.append(f"Error: {result.error}")
        return "\n".join(lines)

    if isinstance(result, PortScanResult):
        lines = [
            f"Host: {result.host}",
            f"Duration: {result.duration:.2f}s",
            "Open ports:" if result.open_ports else "Open ports: none",
        ]
        lines.extend(f"  - {port}" for port in result.open_ports)
        if result.closed_ports:
            lines.append("Closed ports:")
            lines.extend(f"  - {port}: {reason}" for port, reason in result.closed_ports.items())
        return "\n".join(lines)

    if isinstance(result, SubdomainScanResult):
        lines = [
            f"Domain: {result.domain}",
            f"Duration: {result.duration:.2f}s",
        ]
        if result.resolved:
            lines.append("Resolved subdomains:")
            for entry in result.resolved:
                addresses = ", ".join(entry.addresses)
                lines.append(f"  - {entry.hostname}: {addresses}")
        else:
            lines.append("Resolved subdomains: none")

        if result.unresolved:
            lines.append("Unresolved subdomains:")
            for host, reason in result.unresolved.items():
                lines.append(f"  - {host}: {reason}")
        return "\n".join(lines)

    raise TypeError(f"Unsupported result object: {result!r}")


def run(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    _configure_logging(args)

    try:
        result = asyncio.run(_dispatch(args))
    except ScanError as exc:
        logging.error("%s", exc)
        return 2

    output = _format_result(result, args.format)
    print(output)

    if args.output:
        args.output.write_text(json.dumps(_result_to_dict(result), indent=2, sort_keys=True) + "\n")

    return 0


def main(argv: Sequence[str] | None = None) -> int:
    exit_code = run(argv)
    if argv is None:
        sys.exit(exit_code)
    return exit_code


__all__ = ["main", "run", "parse_ports"]
