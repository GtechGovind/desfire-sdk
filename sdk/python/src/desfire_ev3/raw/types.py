"""Typed expert request and response models for the C raw-channel ABI."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, IntFlag

from ..models import Communication
from ..transport import Framing


class NativeFlags(IntFlag):
    """Explicit native continuation behavior."""

    NONE = 0
    SINGLE_CONTINUATION = 1


class IsoLengthEncoding(IntEnum):
    """Requested APDU length representation."""

    AUTOMATIC = 0
    SHORT = 1
    EXTENDED = 2


class SecureProfile(IntEnum):
    """Raw native secure-session family selected by a request."""

    STANDARD_AES = 1
    EV2 = 2


@dataclass(frozen=True)
class NativeRequest:
    """One native logical command with explicit framing and continuation bounds."""

    command: int
    data: bytes = b""
    framing: Framing = Framing.ISO_WRAPPED
    maximum_response: int = 65536
    first_frame_data_size: int | None = None
    flags: NativeFlags = NativeFlags.NONE


@dataclass(frozen=True)
class NativeSecureRequest:
    """Secure native layout supplied without inferred command semantics."""

    profile: SecureProfile
    command: int
    header: bytes = b""
    data: bytes = b""
    request_communication: Communication = Communication.FULL
    response_communication: Communication = Communication.FULL
    minimum_response: int = 0
    maximum_response: int = 65536
    first_frame_data_size: int | None = None
    flags: NativeFlags = NativeFlags.NONE
    invalidates_session: bool = False


@dataclass(frozen=True)
class IsoApdu:
    """Complete true ISO/IEC 7816 APDU description with bounded continuation policy."""

    cla: int
    ins: int
    p1: int
    p2: int
    data: bytes = b""
    le: int | None = None
    length_encoding: IsoLengthEncoding = IsoLengthEncoding.AUTOMATIC
    correct_length: bool = False
    maximum_response: int = 65536
    maximum_frames: int = 32


@dataclass(frozen=True)
class NativeResponse:
    """Status-free native response data paired with the exact status byte."""

    data: bytes
    status: int


@dataclass(frozen=True)
class IsoResponse:
    """ISO response data paired with its exact status word, including warnings."""

    data: bytes
    status_word: int
