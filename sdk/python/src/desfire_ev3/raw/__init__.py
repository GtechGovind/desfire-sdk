"""Expert raw channel and generated ABI operation inventory."""

from typing import TYPE_CHECKING, Any

from .abi import AbiOperation, operations, verify_library
from .operations_generated import ABI_VERSION, MANIFEST_SHA256, OPERATIONS
from .types import (
    IsoApdu,
    IsoLengthEncoding,
    IsoResponse,
    NativeFlags,
    NativeRequest,
    NativeResponse,
    NativeSecureRequest,
    SecureProfile,
)

if TYPE_CHECKING:
    from .card import RawCard


def __getattr__(name: str) -> Any:
    """Load RawCard lazily to keep the ABI manifest free from import cycles."""
    if name == "RawCard":
        from .card import RawCard

        return RawCard
    raise AttributeError(name)


__all__ = [
    "ABI_VERSION",
    "AbiOperation",
    "IsoApdu",
    "IsoLengthEncoding",
    "IsoResponse",
    "MANIFEST_SHA256",
    "NativeFlags",
    "NativeRequest",
    "NativeResponse",
    "NativeSecureRequest",
    "OPERATIONS",
    "RawCard",
    "SecureProfile",
    "operations",
    "verify_library",
]
