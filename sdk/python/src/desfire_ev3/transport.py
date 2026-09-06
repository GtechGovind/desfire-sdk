"""Host-owned reader transport contract for the portable Python SDK."""

from dataclasses import dataclass
from enum import IntEnum
from typing import Protocol


class Framing(IntEnum):
    """Physical framing accepted by the reader callback."""

    NATIVE = 0
    ISO_WRAPPED = 1


@dataclass(frozen=True)
class TransportOptions:
    """Explicit bounded reader capacities; sizes are bytes."""

    framing: Framing = Framing.ISO_WRAPPED
    max_transmit: int = 261
    max_receive: int = 65538
    max_native_frame: int = 60


class Reader(Protocol):
    """Synchronous activated-card transport with no implicit retry or reconnect."""

    def exchange(self, request: bytes, timeout_ms: int) -> bytes:
        """Exchange exactly one physical frame within a positive millisecond budget."""
        ...


class CancellableReader(Reader, Protocol):
    """Reader extension that can interrupt an active exchange."""

    def cancel(self) -> None:
        """Request interruption without waiting for the active exchange to finish."""
        ...


class ResettableReader(Reader, Protocol):
    """Reader extension that can explicitly reset the activated card."""

    def reset(self) -> None:
        """Reset the activated card or raise failure evidence."""
        ...
