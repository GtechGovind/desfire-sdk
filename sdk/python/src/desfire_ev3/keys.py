"""Scoped AES-128 key sources and application-defined resolution contracts."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Protocol, Union

from .errors import DesfireError, ErrorCode, Outcome
from .models import ApplicationId, KeyNumber


def _owned_bytes(value: bytes | bytearray | memoryview, maximum: int, name: str) -> bytes:
    """Validate one contiguous byte-oriented view and retain an immutable snapshot."""
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{name} must be bytes, bytearray, or memoryview")
    view = memoryview(value)
    if view.ndim != 1 or view.itemsize != 1 or not view.c_contiguous or view.nbytes > maximum:
        raise ValueError(f"{name} must be a contiguous byte range of at most {maximum} bytes")
    return bytes(view)


class KeyPurpose(IntEnum):
    """Operation class for which a scoped key is requested."""

    AUTHENTICATION = 0
    CURRENT_KEY = 1
    REPLACEMENT_KEY = 2
    DELEGATED_APPLICATION = 3
    TRANSACTION_MAC = 4
    OFFLINE_OPERATION = 5


class AuthenticationProfile(IntEnum):
    """Authentication family whose card proof and session rules will consume the key."""

    STANDARD_AES = 0
    EV2_FIRST = 1
    EV2_NON_FIRST = 2
    ISO_AES = 3


class KeyScope(IntEnum):
    """Card-side namespace containing the requested key selector."""

    NATIVE = 0
    ISO_PICC = 1
    ISO_APPLICATION = 2


class Aes128Key:
    """Closeable mutable owner of exactly sixteen AES key bytes.

    Python, extension modules, and the operating system may retain copies outside this
    object's control. ``close`` wipes only the bytearray owned by this instance.
    """

    __slots__ = ("_bytes",)

    def __init__(self, value: bytes | bytearray | memoryview) -> None:
        """Copy exactly sixteen caller bytes into independently wipeable storage."""
        view = memoryview(value)
        if view.ndim != 1 or view.itemsize != 1 or not view.c_contiguous or view.nbytes != 16:
            raise ValueError("AES-128 keys must contain exactly sixteen contiguous bytes")
        self._bytes = bytearray(view)

    def __enter__(self) -> Aes128Key:
        """Borrow this live key for one explicit scope."""
        if not self._bytes:
            raise ValueError("AES-128 key has been closed")
        return self

    def __exit__(self, *_: object) -> None:
        """Wipe owned bytes when leaving a context-manager scope."""
        self.close()

    def __del__(self) -> None:
        """Attempt best-effort wiping when explicit close was omitted."""
        self.close()

    def close(self) -> None:
        """Overwrite and release this instance's owned key bytes; repeated calls are safe."""
        storage = getattr(self, "_bytes", None)
        if storage is not None:
            for index in range(len(storage)):
                storage[index] = 0
            storage.clear()

    def snapshot(self) -> bytearray:
        """Return one temporary mutable copy for a native call; caller must wipe it."""
        if len(self._bytes) != 16:
            raise ValueError("AES-128 key has been closed")
        return self._bytes.copy()


@dataclass(frozen=True)
class DerivationContext:
    """Non-secret caller-defined derivation inputs; the SDK does not infer byte order."""

    purpose: KeyPurpose
    key_number: KeyNumber
    application: ApplicationId | None = None
    key_set: int | None = None
    diversification_input: bytes = b""
    user_context: bytes = b""

    def __post_init__(self) -> None:
        """Bound context before provider work or card I/O."""
        object.__setattr__(self, "purpose", KeyPurpose(self.purpose))
        if not isinstance(self.key_number, KeyNumber):
            raise TypeError("key_number must be a KeyNumber")
        if self.application is not None and not isinstance(self.application, ApplicationId):
            raise TypeError("application must be absent or an ApplicationId")
        if self.key_set is not None and (
            not isinstance(self.key_set, int)
            or isinstance(self.key_set, bool)
            or not 0 <= self.key_set <= 15
        ):
            raise ValueError("key_set must be absent or an integer from zero through fifteen")
        diversification = _owned_bytes(
            self.diversification_input,
            65536,
            "diversification_input",
        )
        user_context = _owned_bytes(self.user_context, 65536, "user_context")
        total = len(diversification) + len(user_context)
        if total > 65536:
            raise ValueError("combined derivation context exceeds 65536 bytes")
        object.__setattr__(self, "diversification_input", diversification)
        object.__setattr__(self, "user_context", user_context)


@dataclass(frozen=True)
class KeyRequest:
    """One non-secret provider lookup bound to purpose, profile, and card scope."""

    reference: bytes
    context: DerivationContext
    profile: AuthenticationProfile | None = None
    scope: KeyScope = KeyScope.NATIVE

    def __post_init__(self) -> None:
        """Reject empty or excessively large provider identifiers."""
        reference = _owned_bytes(self.reference, 1024, "key reference")
        if not reference:
            raise ValueError("key reference must contain one through 1024 bytes")
        if not isinstance(self.context, DerivationContext):
            raise TypeError("context must be a DerivationContext")
        object.__setattr__(self, "reference", reference)
        if self.profile is not None:
            object.__setattr__(self, "profile", AuthenticationProfile(self.profile))
        object.__setattr__(self, "scope", KeyScope(self.scope))


class Aes128KeyDeriver(Protocol):
    """Application-defined synchronous derivation executed before native I/O."""

    def derive(self, master_key: Aes128Key, context: DerivationContext) -> Aes128Key:
        """Return a new exact key without retaining the master key or context."""
        ...


class Aes128KeyProvider(Protocol):
    """Application-defined synchronous resolver for exportable AES-128 keys."""

    def resolve(self, request: KeyRequest) -> Aes128Key:
        """Resolve exactly one scoped key without performing card I/O."""
        ...


class AsyncAes128KeyProvider(Protocol):
    """Application-defined asynchronous resolver for exportable AES-128 keys."""

    async def resolve(self, request: KeyRequest) -> Aes128Key:
        """Resolve exactly one scoped key without retaining request data."""
        ...


KeyProvider = Aes128KeyProvider
AsyncKeyProvider = AsyncAes128KeyProvider


@dataclass(frozen=True)
class Direct:
    """Use an already-derived AES-128 key."""

    key: Aes128Key


@dataclass(frozen=True)
class Derived:
    """Derive one scoped key from a master key inside the card operation queue."""

    master_key: Aes128Key
    context: DerivationContext
    deriver: Aes128KeyDeriver


@dataclass(frozen=True)
class Provider:
    """Resolve one scoped key from a non-secret reference inside the card queue."""

    request: KeyRequest
    provider: Aes128KeyProvider


@dataclass(frozen=True)
class AsyncProvider:
    """Resolve one scoped key asynchronously before the first card frame."""

    request: KeyRequest
    provider: AsyncAes128KeyProvider


KeySource = Union[Direct, Derived, Provider]
AsyncKeySource = Union[Direct, Derived, Provider, AsyncProvider]


def resolve_key_source(
    source: KeySource,
    key_number: KeyNumber,
    profile: AuthenticationProfile | None,
    scope: KeyScope,
    purpose: KeyPurpose = KeyPurpose.AUTHENTICATION,
) -> bytearray:
    """Resolve one temporary exact key before I/O and redact callback failures.

    The caller owns the returned mutable snapshot and must overwrite it on every exit path.
    Derivers and providers execute exactly once. Their exceptions and messages never cross the
    SDK boundary because they may contain private routing or key-system details.
    """
    if not isinstance(key_number, KeyNumber):
        raise TypeError("key_number must be a KeyNumber")
    if not isinstance(source, (Direct, Derived, Provider)):
        raise TypeError("key source must be Direct, Derived, or Provider")
    profile = AuthenticationProfile(profile) if profile is not None else None
    scope = KeyScope(scope)
    purpose = KeyPurpose(purpose)
    try:
        if isinstance(source, Direct):
            return source.key.snapshot()
        if isinstance(source, Derived):
            context = source.context
            if context.purpose is not purpose:
                raise ValueError("derivation context purpose does not match the operation")
            if context.key_number != key_number:
                raise ValueError("derivation context key number does not match the operation")
            resolved = source.deriver.derive(source.master_key, context)
        elif isinstance(source, Provider):
            request = source.request
            if request.context.purpose is not purpose:
                raise ValueError("provider request purpose does not match the operation")
            if request.context.key_number != key_number:
                raise ValueError("provider request key number does not match the operation")
            if request.profile is not profile or request.scope is not scope:
                raise ValueError("provider request profile or scope does not match the operation")
            resolved = source.provider.resolve(request)
        if not isinstance(resolved, Aes128Key):
            raise TypeError("key callback must return Aes128Key")
        try:
            return resolved.snapshot()
        finally:
            resolved.close()
    except DesfireError as failure:
        raise DesfireError(
            failure.code,
            "AES-128 key resolution failed",
            Outcome.NOT_SENT,
        ) from None
    except BaseException:
        raise DesfireError(
            ErrorCode.CRYPTO,
            "AES-128 key resolution failed",
            Outcome.NOT_SENT,
        ) from None
