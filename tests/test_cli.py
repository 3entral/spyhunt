import argparse
import asyncio
import importlib
import json
import socket

import pytest

from spyhunt.main import parse_ports, run


@pytest.mark.parametrize(
    "spec,expected",
    [
        ("80", [80]),
        ("80,443", [80, 443]),
        ("80-82", [80, 81, 82]),
        ("22,80-82", [22, 80, 81, 82]),
    ],
)
def test_parse_ports_success(spec, expected):
    assert parse_ports(spec) == expected


@pytest.mark.parametrize("spec", ["", "abc", "0", "70000", "10-5", "1,,2"])
def test_parse_ports_validation(spec):
    with pytest.raises(argparse.ArgumentTypeError):
        parse_ports(spec)


def test_run_http(monkeypatch, tmp_path, capsys):
    import importlib

    cli = importlib.import_module("spyhunt.main")
    from spyhunt.scanners.http import HttpScanResult

    async def fake_dispatch(args):
        assert args.command == "http"
        return HttpScanResult(
            url="https://example.com/",
            status=200,
            headers={"Server": "Example"},
            redirects=[],
            technologies=["Example"],
            duration=0.1,
        )

    monkeypatch.setattr(cli, "_dispatch", fake_dispatch)

    args = [
        "--format",
        "json",
        "--output",
        str(tmp_path / "output.json"),
        "http",
        "https://example.com",
    ]

    exit_code = run(args)
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["status"] == 200
    assert json.loads((tmp_path / "output.json").read_text())["url"] == "https://example.com/"


def test_http_scanner_detects_headers(unused_tcp_port):
    from aiohttp import web

    async def runner():
        async def handler(request):
            return web.Response(
                text="<html><body>Django site</body></html>",
                headers={"Server": "nginx", "X-Powered-By": "Django"},
            )

        app = web.Application()
        app.router.add_get("/", handler)

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", unused_tcp_port)
        await site.start()

        port = site._server.sockets[0].getsockname()[1]
        from spyhunt.scanners.http import HttpScanner

        scanner = HttpScanner(f"http://127.0.0.1:{port}")
        result = await scanner.scan()

        assert result.status == 200
        assert "nginx" in {tech.lower() for tech in result.technologies}
        assert any("django" in tech.lower() for tech in result.technologies)

        await runner.cleanup()

    asyncio.run(runner())


def test_run_subdomains(monkeypatch, tmp_path, capsys):
    cli = importlib.import_module("spyhunt.main")
    from spyhunt.scanners.subdomains import ResolvedSubdomain, SubdomainScanResult

    async def fake_dispatch(args):
        assert args.command == "subdomains"
        return SubdomainScanResult(
            domain="example.com",
            resolved=[
                ResolvedSubdomain(
                    hostname="www.example.com",
                    addresses=["93.184.216.34"],
                )
            ],
            unresolved={"api.example.com": "not found"},
            duration=0.2,
        )

    monkeypatch.setattr(cli, "_dispatch", fake_dispatch)

    args = [
        "--format",
        "json",
        "--output",
        str(tmp_path / "subdomains.json"),
        "subdomains",
        "example.com",
    ]

    exit_code = run(args)
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["resolved"][0]["hostname"] == "www.example.com"
    written = json.loads((tmp_path / "subdomains.json").read_text())
    assert written["unresolved"]["api.example.com"] == "not found"


def test_subdomain_scanner(monkeypatch):
    async def runner():
        from spyhunt.scanners.subdomains import SubdomainScanner

        loop = asyncio.get_running_loop()

        async def fake_getaddrinfo(host, port, *args, **kwargs):
            if host == "www.example.com":
                return [
                    (
                        socket.AF_INET,
                        socket.SOCK_STREAM,
                        6,
                        "",
                        ("93.184.216.34", 0),
                    ),
                    (
                        socket.AF_INET6,
                        socket.SOCK_STREAM,
                        6,
                        "",
                        ("2606:2800:220:1:248:1893:25c8:1946", 0),
                    ),
                ]
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

        monkeypatch.setattr(loop, "getaddrinfo", fake_getaddrinfo)

        scanner = SubdomainScanner(
            "example.com",
            candidates=["www", "api"],
            timeout=0.5,
            concurrency=2,
        )
        result = await scanner.scan()

        hosts = {entry.hostname: entry.addresses for entry in result.resolved}
        assert "www.example.com" in hosts
        assert "93.184.216.34" in hosts["www.example.com"]
        assert "api.example.com" in result.unresolved

    asyncio.run(runner())


def test_port_scanner_finds_open_port(unused_tcp_port):
    async def runner():
        async def handle(reader, writer):
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(handle, "127.0.0.1", unused_tcp_port)
        from spyhunt.scanners.ports import PortScanner

        scanner = PortScanner("127.0.0.1", [unused_tcp_port, unused_tcp_port + 1], timeout=0.5)
        result = await scanner.scan()

        assert unused_tcp_port in result.open_ports
        assert unused_tcp_port + 1 in result.closed_ports

        server.close()
        await server.wait_closed()

    asyncio.run(runner())
