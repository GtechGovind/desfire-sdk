"""Validated public value objects for the friendly Python API."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Union


def _bounded(value: int, minimum: int, maximum: int, name: str) -> int:
    """Validate an exact integer range without accepting floats or coercible strings."""
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer from {minimum} through {maximum}")
    return value


@dataclass(frozen=True)
class ApplicationId:
    """Native three-byte application identifier; zero denotes the PICC."""

    value: int

    def __post_init__(self) -> None:
        """Reject values that cannot be encoded in the native AID field."""
        _bounded(self.value, 0, 0xFFFFFF, "application id")


@dataclass(frozen=True)
class FileNumber:
    """Native five-bit file number."""

    value: int

    def __post_init__(self) -> None:
        """Reject values outside the EV3 native file-number domain."""
        _bounded(self.value, 0, 31, "file number")


@dataclass(frozen=True)
class KeyNumber:
    """Native-width key selector; individual operations may apply narrower limits."""

    value: int

    def __post_init__(self) -> None:
        """Reject values outside the six-bit native selector domain."""
        _bounded(self.value, 0, 63, "key number")


@dataclass(frozen=True)
class Offset:
    """Nonnegative native three-byte byte or record offset."""

    value: int

    def __post_init__(self) -> None:
        """Reject values outside the native three-byte field."""
        _bounded(self.value, 0, 0xFFFFFF, "offset")


class Communication(IntEnum):
    """Documented native file communication policy."""

    PLAIN = 0
    MAC = 1
    FULL = 3


@dataclass(frozen=True)
class AuthenticationInfo:
    """Verified public metadata returned by EV2 authentication."""

    transaction_identifier: bytes
    picc_capabilities: bytes
    pcd_capabilities: bytes

    def __post_init__(self) -> None:
        """Require the fixed EV2 metadata widths before exposing the value."""
        if len(self.transaction_identifier) != 4:
            raise ValueError("transaction_identifier must contain four bytes")
        if len(self.picc_capabilities) != 6 or len(self.pcd_capabilities) != 6:
            raise ValueError("EV2 capability records must contain six bytes")


@dataclass(frozen=True)
class DelegatedApplicationInfo:
    """Decoded counters and application identity for one delegated slot."""

    slot_version: int
    quota_limit: int
    free_blocks: int
    application: ApplicationId

    def __post_init__(self) -> None:
        """Validate C output before exposing it as trusted typed data."""
        _bounded(self.slot_version, 0, 0xFF, "slot version")
        _bounded(self.quota_limit, 0, 0xFFFF, "quota limit")
        _bounded(self.free_blocks, 0, 0xFFFF, "free blocks")
        if not isinstance(self.application, ApplicationId):
            raise TypeError("application must be an ApplicationId")


@dataclass(frozen=True)
class DelegatedApplicationConfiguration:
    """Application fields authenticated by delegated-creation authorization."""

    application: ApplicationId
    key_settings: int
    number_of_keys: int
    slot: int
    slot_version: int
    quota_limit: int
    iso_file_identifiers: bool = False
    key_settings3: int | None = None
    iso_id: int | None = None
    df_name: bytes = b""
    active_key_set_version: int | None = None
    number_of_key_sets: int = 0
    maximum_key_size: int = 0
    key_set_settings: int = 0

    def __post_init__(self) -> None:
        """Validate the complete descriptor before native cryptographic processing."""
        if not isinstance(self.application, ApplicationId) or self.application.value == 0:
            raise ValueError("delegated application requires a nonzero ApplicationId")
        for name, value, maximum in (
            ("key_settings", self.key_settings, 0xFF),
            ("number_of_keys", self.number_of_keys, 0xFF),
            ("slot", self.slot, 0xFFFF),
            ("slot_version", self.slot_version, 0xFF),
            ("quota_limit", self.quota_limit, 0xFFFF),
        ):
            _bounded(value, 0, maximum, name)
        if not isinstance(self.iso_file_identifiers, bool):
            raise TypeError("iso_file_identifiers must be a bool")
        if self.key_settings3 is not None:
            _bounded(self.key_settings3, 0, 0xFF, "key_settings3")
        if self.iso_id is not None:
            _bounded(self.iso_id, 0, 0xFFFF, "iso_id")
        if not isinstance(self.df_name, bytes) or len(self.df_name) > 16:
            raise ValueError("df_name must contain zero through sixteen immutable bytes")
        if self.active_key_set_version is None:
            if any((self.number_of_key_sets, self.maximum_key_size, self.key_set_settings)):
                raise ValueError("absent key-set configuration requires zero key-set fields")
        else:
            for name, value in (
                ("active_key_set_version", self.active_key_set_version),
                ("number_of_key_sets", self.number_of_key_sets),
                ("maximum_key_size", self.maximum_key_size),
                ("key_set_settings", self.key_set_settings),
            ):
                _bounded(value, 0, 0xFF, name)


@dataclass(frozen=True)
class PiccConfiguration:
    """Named SetConfiguration option-zero flags."""

    disable_format: bool = False
    random_identifier: bool = False
    proximity_check_mandatory: bool = False
    virtual_card_authentication_mandatory: bool = False
    error_code_binding: bool = False
    random_identifier_configuration: bool = False
    four_byte_nuid_configuration: bool = False

    def __post_init__(self) -> None:
        """Reject integer lookalikes so every flag remains explicit."""
        for name, value in vars(self).items():
            if not isinstance(value, bool):
                raise TypeError(f"{name} must be a bool")


class TransactionKind(IntEnum):
    """Checked mutation kinds accepted by one managed transaction plan."""

    WRITE_DATA = 1
    CREDIT = 2
    DEBIT = 3
    LIMITED_CREDIT = 4
    WRITE_RECORD = 5
    UPDATE_RECORD = 6
    CLEAR_RECORD_FILE = 7


@dataclass(frozen=True)
class TransactionOperation:
    """One validated mutation executed under a single managed-card admission."""

    kind: TransactionKind
    file: FileNumber
    communication: Communication
    offset: Offset = Offset(0)
    record: int = 0
    amount: int = 0
    data: bytes = b""

    def __post_init__(self) -> None:
        """Bound every descriptor field before any transaction can reach the card."""
        object.__setattr__(self, "kind", TransactionKind(self.kind))
        object.__setattr__(self, "communication", Communication(self.communication))
        if not isinstance(self.file, FileNumber) or not isinstance(self.offset, Offset):
            raise TypeError("file and offset require their strong identifier types")
        _bounded(self.record, 0, 0xFFFFFF, "record")
        _bounded(self.amount, 0, 0xFFFFFFFF, "amount")
        if not isinstance(self.data, bytes):
            raise TypeError("transaction data must be immutable bytes")
        if len(self.data) > 0xFFFFFF:
            raise ValueError("transaction data exceeds the native three-byte length")


@dataclass(frozen=True)
class TransactionReceipt:
    """Commit result containing the optional transaction-MAC response bytes."""

    transaction_mac: bytes


class UidOption(IntEnum):
    """Documented GetCardUID output selection."""

    OMITTED = 0
    WITHOUT_NUID = 1
    WITH_NUID = 2


Binary = Union[bytes, bytearray, memoryview]
