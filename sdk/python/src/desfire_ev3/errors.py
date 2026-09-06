"""Stable failure and delivery evidence shared by friendly and raw Python APIs."""

from enum import IntEnum


class Outcome(IntEnum):
    """Best available evidence about whether an operation reached the card."""

    NOT_SENT = 0
    REJECTED = 1
    SUCCEEDED = 2
    UNKNOWN = 3


class ErrorCode(IntEnum):
    """Stable error categories published by C ABI version 1."""

    INVALID_ARGUMENT = 1
    TRANSPORT = 2
    CARD_REMOVED = 3
    TIMEOUT = 4
    CANCELLED = 5
    MALFORMED_RESPONSE = 6
    CARD_REJECTED = 7
    AUTHENTICATION = 8
    INTEGRITY = 9
    UNSUPPORTED = 10
    STALE_HANDLE = 11
    BUSY = 12
    SESSION_INVALID = 13
    COUNTER_EXHAUSTED = 14
    BUFFER_TOO_SMALL = 15
    CRYPTO = 16
    INTERNAL = 17


class DesfireError(RuntimeError):
    """One redacted failure with exact native status and delivery evidence."""

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        outcome: Outcome = Outcome.UNKNOWN,
        device_status: int = 0,
    ) -> None:
        """Retain bounded evidence needed for safe recovery and reconciliation."""
        super().__init__(message)
        self.code = ErrorCode(code)
        self.outcome = Outcome(outcome)
        if not isinstance(device_status, int) or not 0 <= device_status <= 0xFFFF:
            raise ValueError("device_status must fit an unsigned 16-bit status word")
        self.device_status = device_status

    @property
    def requires_reconciliation(self) -> bool:
        """Return true when a mutation may have reached the card without a final result."""
        return self.outcome is Outcome.UNKNOWN
