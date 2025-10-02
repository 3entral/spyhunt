"""Base classes and helpers for scanner implementations."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Generic, TypeVar


T = TypeVar("T")


class ScanError(RuntimeError):
    """Raised when a scanner fails to collect results."""


@dataclass(slots=True)
class ScanResult:
    """Common result information returned by scanners."""

    duration: float


class Scanner(ABC, Generic[T]):
    """Abstract base class for async scanner implementations."""

    @abstractmethod
    async def scan(self) -> T:
        """Execute the scanner and return a result object."""
        raise NotImplementedError
