# Refactored architecture overview

The 4.x refactor of Spyhunt focuses on maintainability and testability. The
legacy code base consisted of a single, monolithic script that handled command
line parsing, output formatting and all scanning logic in one file. That design
made it difficult to reason about, extend and test the individual features.

## Package layout

```
spyhunt/
├── __init__.py          # Public API exports
├── main.py              # CLI orchestration and argument parsing
└── scanners/
    ├── __init__.py      # Re-export of available scanners
    ├── base.py          # Shared interfaces and result dataclasses
    ├── http.py          # HTTP reconnaissance implementation
    ├── ports.py         # TCP port scanning implementation
    └── subdomains.py    # DNS driven subdomain enumeration
```

Each scanner module exposes a concrete implementation of
`spyhunt.scanners.base.Scanner` and returns a dataclass that inherits from
`spyhunt.scanners.base.ScanResult`. This ensures that every scanner captures a
runtime duration and can be serialised to JSON in a consistent way.

## Command line interface

The CLI (`spyhunt.main`) uses `argparse` sub-commands to keep responsibilities
clear. Each sub-command constructs the appropriate scanner (HTTP, ports, or
subdomain enumeration) and awaits the result via `asyncio.run`. Results are
formatted either as JSON (default) or human readable text and can optionally be
written to disk.

Logging levels can be adjusted with `--verbose` and `--debug`. All exceptions
raised by scanners are wrapped in `ScanError` so that the CLI has a single error
path with helpful messaging.

## Testing strategy

The test-suite relies on `pytest` and spins up lightweight local services during
tests:

- `aiohttp.web` is used to emulate HTTP responses with specific headers so that
  the fingerprinting heuristics can be verified without external dependencies.
- `asyncio.start_server` provides an in-process TCP listener used by the port
  scanner tests.

The CLI is tested with a patched dispatcher to avoid hitting the network while
still exercising argument parsing, result formatting and file output.

## Adding new scanners

To add a new reconnaissance capability:

1. Implement a scanner module under `spyhunt/scanners/` that subclasses
   `Scanner` and returns a dataclass result.
2. Re-export the scanner in `spyhunt/scanners/__init__.py` and in the package
   `__init__` if you want it to be part of the public API.
3. Register a new sub-command inside `spyhunt/main.py` that instantiates the
   scanner and formats the result.
4. Write focused tests that emulate the target behaviour.

This approach keeps each capability isolated and encourages a culture of small,
well-tested contributions instead of sprawling scripts.
