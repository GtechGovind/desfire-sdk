"""Complete expert raw channel over the stable C99 ABI."""

from __future__ import annotations

import ctypes as ct
import os
import threading
from datetime import timedelta
from typing import Any, Callable, TypeVar

from .._card import (
    _AuthenticationInfo,
    _Callbacks,
    _check,
    _claim_reader,
    _Error,
    _integer,
    _IsoApdu,
    _Library,
    _NativeRequest,
    _NativeSecureRequest,
    _Release,
    _release_reader,
    _Retain,
    _Transport,
)
from ..card import _timeout_ms
from ..errors import DesfireError, ErrorCode, Outcome
from ..keys import AuthenticationProfile, KeyScope, KeySource, resolve_key_source
from ..models import AuthenticationInfo, KeyNumber
from ..transport import Framing, Reader, TransportOptions
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

T = TypeVar("T")
_NO_BOUNDARY = ct.c_size_t(-1).value
SUPPORTED_C_SYMBOLS = frozenset(
    {
        "df_raw_open",
        "df_raw_close",
        "df_raw_reset",
        "df_raw_cancel",
        "df_raw_notify_state_change",
        "df_raw_native_frame",
        "df_raw_native_exchange",
        "df_raw_iso_exchange",
        "df_raw_authenticate_standard_aes",
        "df_raw_authenticate_standard_aes_provider",
        "df_raw_authenticate_ev2_first_aes",
        "df_raw_authenticate_ev2_first_aes_provider",
        "df_raw_authenticate_ev2_non_first_aes",
        "df_raw_authenticate_ev2_non_first_aes_provider",
        "df_raw_authenticate_iso_aes",
        "df_raw_authenticate_iso_aes_provider",
        "df_raw_iso_secure_exchange",
        "df_raw_native_secure_exchange",
    }
)


def _bytes(value: bytes, name: str, maximum: int = 16 * 1024 * 1024) -> tuple[Any, int]:
    """Copy one bounded immutable byte string into stable call-owned C storage."""
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be immutable bytes")
    if len(value) > maximum:
        raise ValueError(f"{name} exceeds {maximum} bytes")
    return (ct.c_uint8 * len(value)).from_buffer_copy(value), len(value)


def _auth_info(value: _AuthenticationInfo) -> AuthenticationInfo:
    """Convert verified fixed-layout native authentication metadata."""
    return AuthenticationInfo(
        bytes(value.transaction_identifier),
        bytes(value.picc_capabilities),
        bytes(value.pcd_capabilities),
    )


class RawCard:
    """Own an independent raw channel with FIFO logical-operation admission.

    Requests preserve exact native or ISO status and never infer secure command layout. The same
    reader instance cannot back a managed Card and RawCard at the same time.
    """

    def __init__(
        self,
        library: str | os.PathLike[str],
        reader: Reader,
        options: TransportOptions = TransportOptions(),
    ) -> None:
        """Open a raw channel without card I/O and retain callback ownership."""
        self._handle = 0
        self._condition = threading.Condition()
        self._next_ticket = 0
        self._serving_ticket = 0
        self._active_thread: int | None = None
        self._closing = False
        self._reader_claim = object()
        _claim_reader(reader, self._reader_claim)
        try:
            framing = Framing(options.framing)
            maximum_transmit = _integer(options.max_transmit, 6, 16 * 1024 * 1024, "max_transmit")
            maximum_receive = _integer(options.max_receive, 2, 16 * 1024 * 1024, "max_receive")
            maximum_frame = _integer(
                options.max_native_frame,
                2,
                maximum_transmit,
                "max_native_frame",
            )
            self._library = _Library(library)
            self._callbacks = _Callbacks(reader)
            self._transport = _Transport(
                ct.sizeof(_Transport),
                1,
                int(framing),
                maximum_transmit,
                maximum_receive,
                maximum_frame,
                None,
                self._callbacks.exchange,
                self._callbacks.cancel,
                self._callbacks.reset,
                _Retain(),
                _Release(),
                (ct.c_uint64 * 8)(),
            )
            handle = ct.c_uint64()
            error = _Error()
            status = self._library.native.df_raw_open(
                ct.byref(self._transport),
                ct.byref(handle),
                ct.byref(error),
            )
            _check(status, error)
            self._handle = handle.value
        except BaseException:
            _release_reader(reader, self._reader_claim)
            raise

    def __enter__(self) -> RawCard:
        """Borrow this live channel for a context-manager scope."""
        self._require_open()
        return self

    def __exit__(self, *_: object) -> None:
        """Close the raw channel on every context-manager exit path."""
        self.close()

    def __del__(self) -> None:
        """Attempt best-effort cleanup when explicit close was omitted."""
        try:
            self.close()
        except BaseException:
            pass

    @property
    def closed(self) -> bool:
        """Return whether native and callback ownership has been released."""
        return self._handle == 0

    def _require_open(self) -> int:
        """Read a live handle without waiting for an active exchange."""
        with self._condition:
            if not self._handle or self._closing:
                raise DesfireError(
                    ErrorCode.STALE_HANDLE, "Raw channel is closed", Outcome.NOT_SENT
                )
            return self._handle

    def _enter(self) -> int:
        """Admit one FIFO operation and reject callback reentry."""
        thread = threading.get_ident()
        with self._condition:
            if not self._handle or self._closing:
                raise DesfireError(
                    ErrorCode.STALE_HANDLE, "Raw channel is closed", Outcome.NOT_SENT
                )
            if self._active_thread == thread:
                raise DesfireError(
                    ErrorCode.BUSY, "Raw callback reentry is not allowed", Outcome.NOT_SENT
                )
            ticket = self._next_ticket
            self._next_ticket += 1
            while ticket != self._serving_ticket:
                self._condition.wait()
            self._active_thread = thread
            return self._handle

    def _leave(self) -> None:
        """Advance FIFO admission after native references have expired."""
        with self._condition:
            self._active_thread = None
            self._serving_ticket += 1
            self._condition.notify_all()

    def _operation(self, invoke: Callable[[int], T]) -> T:
        """Run one closure under FIFO admission without retrying it."""
        handle = self._enter()
        try:
            return invoke(handle)
        finally:
            self._leave()

    def close(self) -> None:
        """Reject new work, drain admitted operations, and release the channel once."""
        thread = threading.get_ident()
        with self._condition:
            if not self._handle:
                return
            if self._active_thread == thread:
                raise DesfireError(
                    ErrorCode.BUSY, "Raw callback cannot close its channel", Outcome.NOT_SENT
                )
            if self._closing:
                while self._closing and self._handle:
                    self._condition.wait()
                if not self._handle:
                    return
            self._closing = True
            while self._serving_ticket != self._next_ticket or self._active_thread is not None:
                self._condition.wait()
            handle = self._handle
        error = _Error()
        try:
            _check(self._library.native.df_raw_close(handle, ct.byref(error)), error)
        except BaseException:
            with self._condition:
                self._closing = False
                self._condition.notify_all()
            raise
        with self._condition:
            self._handle = 0
            self._closing = False
            self._condition.notify_all()
        _release_reader(self._callbacks.reader, self._reader_claim)

    def _lifecycle(self, symbol: str, allow_closing: bool = False) -> None:
        """Invoke a lock-independent raw lifecycle operation."""
        if allow_closing:
            with self._condition:
                if not self._handle:
                    raise DesfireError(
                        ErrorCode.STALE_HANDLE, "Raw channel is closed", Outcome.NOT_SENT
                    )
                handle = self._handle
        else:
            handle = self._require_open()
        error = _Error()
        _check(getattr(self._library.native, symbol)(handle, ct.byref(error)), error)

    def reset(self) -> None:
        """Reset the transport and erase all raw secure sessions."""
        self._lifecycle("df_raw_reset")

    def notify_state_change(self) -> None:
        """Invalidate raw session state after host-observed card replacement."""
        self._lifecycle("df_raw_notify_state_change")

    def cancel(self) -> None:
        """Request reader cancellation without waiting for an active raw operation."""
        self._callbacks.cancel_errors.failure = None
        self._lifecycle("df_raw_cancel", allow_closing=True)
        failure = self._callbacks.cancel_errors.failure
        if failure is not None:
            raise failure

    def _copy_result(self, result: ct.c_void_p) -> bytes:
        """Copy and validate one owned native output, then release it."""
        if not result.value:
            raise DesfireError(ErrorCode.INTERNAL, "Native raw operation returned no buffer")
        try:
            size = self._library.native.df_buffer_size(result)
            data = self._library.native.df_buffer_data(result)
            if size > 16 * 1024 * 1024 or (size and not data):
                raise DesfireError(ErrorCode.INTERNAL, "Native raw output is invalid")
            return ct.string_at(data, size)
        finally:
            self._library.native.df_buffer_free(result)

    def native_frame(
        self,
        command: int,
        data: bytes = b"",
        framing: Framing = Framing.ISO_WRAPPED,
        timeout: timedelta = timedelta(seconds=5),
    ) -> NativeResponse:
        """Exchange exactly one physical native frame and preserve its status byte."""
        command = _integer(command, 0, 0xFF, "command")
        framing = Framing(framing)
        owner, size = _bytes(data, "data")

        def invoke(handle: int) -> NativeResponse:
            status_word = ct.c_uint32()
            result = ct.c_void_p()
            error = _Error()
            status = self._library.native.df_raw_native_frame(
                handle,
                int(framing),
                command,
                owner,
                size,
                _timeout_ms(timeout),
                ct.byref(status_word),
                ct.byref(result),
                ct.byref(error),
            )
            _check(status, error)
            return NativeResponse(self._copy_result(result), status_word.value)

        return self._operation(invoke)

    def native_exchange(
        self,
        request: NativeRequest,
        timeout: timedelta = timedelta(seconds=5),
    ) -> NativeResponse:
        """Exchange one bounded native logical command with explicit AF policy."""
        if not isinstance(request, NativeRequest):
            raise TypeError("request must be NativeRequest")
        owner, size = _bytes(request.data, "data")
        maximum = _integer(request.maximum_response, 1, 16 * 1024 * 1024, "maximum_response")
        boundary = (
            _NO_BOUNDARY
            if request.first_frame_data_size is None
            else _integer(
                request.first_frame_data_size,
                0,
                size,
                "first_frame_data_size",
            )
        )
        descriptor = _NativeRequest(
            ct.sizeof(_NativeRequest),
            1,
            int(Framing(request.framing)),
            _integer(request.command, 0, 0xFF, "command"),
            owner,
            size,
            maximum,
            boundary,
            int(NativeFlags(request.flags)),
            0,
            (ct.c_uint64 * 8)(),
        )

        def invoke(handle: int) -> NativeResponse:
            native_status = ct.c_uint32()
            result = ct.c_void_p()
            error = _Error()
            status = self._library.native.df_raw_native_exchange(
                handle,
                ct.byref(descriptor),
                _timeout_ms(timeout),
                ct.byref(native_status),
                ct.byref(result),
                ct.byref(error),
            )
            _check(status, error)
            return NativeResponse(self._copy_result(result), native_status.value)

        return self._operation(invoke)

    @staticmethod
    def _iso_descriptor(request: IsoApdu) -> tuple[_IsoApdu, Any]:
        """Validate and marshal a complete ISO APDU descriptor."""
        if not isinstance(request, IsoApdu):
            raise TypeError("request must be IsoApdu")
        owner, size = _bytes(request.data, "data", 65535)
        for name in ("cla", "ins", "p1", "p2"):
            _integer(getattr(request, name), 0, 0xFF, name)
        if request.le is None:
            has_le, le = 0, 0
        else:
            has_le, le = 1, _integer(request.le, 1, 65536, "le")
        if not isinstance(request.correct_length, bool):
            raise TypeError("correct_length must be a bool")
        descriptor = _IsoApdu(
            ct.sizeof(_IsoApdu),
            1,
            request.cla,
            request.ins,
            request.p1,
            request.p2,
            owner,
            size,
            has_le,
            le,
            int(IsoLengthEncoding(request.length_encoding)),
            int(request.correct_length),
            _integer(request.maximum_response, 1, 16 * 1024 * 1024, "maximum_response"),
            _integer(request.maximum_frames, 1, 1024, "maximum_frames"),
            (ct.c_uint64 * 8)(),
        )
        return descriptor, owner

    def _iso_exchange(
        self,
        symbol: str,
        request: IsoApdu,
        timeout: timedelta,
    ) -> IsoResponse:
        """Execute a raw or checked-secure ISO exchange and preserve its status word."""
        descriptor, owner = self._iso_descriptor(request)

        def invoke(handle: int) -> IsoResponse:
            iso_status = ct.c_uint32()
            result = ct.c_void_p()
            error = _Error()
            status = getattr(self._library.native, symbol)(
                handle,
                ct.byref(descriptor),
                _timeout_ms(timeout),
                ct.byref(iso_status),
                ct.byref(result),
                ct.byref(error),
            )
            _check(status, error)
            return IsoResponse(self._copy_result(result), iso_status.value)

        response = self._operation(invoke)
        del owner
        return response

    def iso_exchange(
        self,
        request: IsoApdu,
        timeout: timedelta = timedelta(seconds=5),
    ) -> IsoResponse:
        """Exchange one true ISO APDU, including valid warning responses."""
        return self._iso_exchange("df_raw_iso_exchange", request, timeout)

    def iso_secure_exchange(
        self,
        request: IsoApdu,
        timeout: timedelta = timedelta(seconds=5),
    ) -> IsoResponse:
        """Execute a checked ISO data command through the active raw ISO AES session."""
        return self._iso_exchange("df_raw_iso_secure_exchange", request, timeout)

    def native_secure_exchange(
        self,
        request: NativeSecureRequest,
        timeout: timedelta = timedelta(seconds=5),
    ) -> bytes:
        """Execute an explicit secure-native request without guessing its field layout."""
        if not isinstance(request, NativeSecureRequest):
            raise TypeError("request must be NativeSecureRequest")
        header, header_size = _bytes(request.header, "header")
        data, data_size = _bytes(request.data, "data")
        boundary = (
            _NO_BOUNDARY
            if request.first_frame_data_size is None
            else _integer(
                request.first_frame_data_size,
                0,
                header_size + data_size,
                "first_frame_data_size",
            )
        )
        if not isinstance(request.invalidates_session, bool):
            raise TypeError("invalidates_session must be a bool")
        descriptor = _NativeSecureRequest(
            ct.sizeof(_NativeSecureRequest),
            1,
            int(SecureProfile(request.profile)),
            _integer(request.command, 0, 0xFF, "command"),
            header,
            header_size,
            data,
            data_size,
            int(request.request_communication),
            int(request.response_communication),
            _integer(request.minimum_response, 0, 16 * 1024 * 1024, "minimum_response"),
            _integer(request.maximum_response, 1, 16 * 1024 * 1024, "maximum_response"),
            boundary,
            int(NativeFlags(request.flags)),
            int(request.invalidates_session),
            (ct.c_uint64 * 8)(),
        )
        if descriptor.minimum_response > descriptor.maximum_response:
            raise ValueError("minimum_response cannot exceed maximum_response")

        def invoke(handle: int) -> bytes:
            result = ct.c_void_p()
            error = _Error()
            status = self._library.native.df_raw_native_secure_exchange(
                handle,
                ct.byref(descriptor),
                _timeout_ms(timeout),
                ct.byref(result),
                ct.byref(error),
            )
            _check(status, error)
            return self._copy_result(result)

        return self._operation(invoke)

    def _authenticate(
        self,
        symbol: str,
        key_number: KeyNumber,
        source: KeySource,
        profile: AuthenticationProfile,
        scope: KeyScope,
        timeout: timedelta,
        prefix: tuple[Any, ...] = (),
        metadata: bool = False,
        prefix_before_key: bool = False,
    ) -> AuthenticationInfo | None:
        """Resolve one scoped key inside FIFO admission and establish one raw session."""
        handle = self._enter()
        temporary = bytearray()
        owner: Any = None
        try:
            temporary = resolve_key_source(source, key_number, profile, scope)
            owner = (ct.c_uint8 * len(temporary)).from_buffer_copy(temporary)
            if prefix_before_key:
                converted = [
                    handle,
                    key_number.value,
                    *prefix,
                    owner,
                    len(temporary),
                    _timeout_ms(timeout),
                ]
            else:
                converted = [
                    handle,
                    key_number.value,
                    owner,
                    len(temporary),
                    *prefix,
                    _timeout_ms(timeout),
                ]
            output = _AuthenticationInfo()
            if metadata:
                output.struct_size = ct.sizeof(_AuthenticationInfo)
                output.abi_version = 1
                converted.append(ct.byref(output))
            error = _Error()
            converted.append(ct.byref(error))
            _check(getattr(self._library.native, symbol)(*converted), error)
            return _auth_info(output) if metadata else None
        finally:
            if owner is not None:
                ct.memset(ct.addressof(owner), 0, ct.sizeof(owner))
            temporary[:] = bytes(len(temporary))
            self._leave()

    def authenticate_standard_aes(
        self,
        key_number: KeyNumber,
        source: KeySource,
        timeout: timedelta = timedelta(seconds=5),
    ) -> None:
        """Install a Standard AES session from a direct, derived, or provider source."""
        self._authenticate(
            "df_raw_authenticate_standard_aes",
            key_number,
            source,
            AuthenticationProfile.STANDARD_AES,
            KeyScope.NATIVE,
            timeout,
        )

    def authenticate_ev2_first_aes(
        self,
        key_number: KeyNumber,
        source: KeySource,
        pcd_capabilities: bytes = b"",
        timeout: timedelta = timedelta(seconds=5),
    ) -> AuthenticationInfo:
        """Install EV2 First with zero through six explicit capability bytes."""
        capabilities, size = _bytes(pcd_capabilities, "pcd_capabilities", 6)
        result = self._authenticate(
            "df_raw_authenticate_ev2_first_aes",
            key_number,
            source,
            AuthenticationProfile.EV2_FIRST,
            KeyScope.NATIVE,
            timeout,
            (capabilities, size),
            True,
        )
        assert result is not None
        return result

    def authenticate_ev2_non_first_aes(
        self,
        key_number: KeyNumber,
        source: KeySource,
        timeout: timedelta = timedelta(seconds=5),
    ) -> AuthenticationInfo:
        """Replace an active EV2 session while preserving transaction identity and counter."""
        result = self._authenticate(
            "df_raw_authenticate_ev2_non_first_aes",
            key_number,
            source,
            AuthenticationProfile.EV2_NON_FIRST,
            KeyScope.NATIVE,
            timeout,
            metadata=True,
        )
        assert result is not None
        return result

    def authenticate_iso_aes(
        self,
        key_number: KeyNumber,
        source: KeySource,
        application: bool = False,
        timeout: timedelta = timedelta(seconds=5),
    ) -> None:
        """Install an ISO mutual AES session in PICC or application scope."""
        if not isinstance(application, bool):
            raise TypeError("application must be a bool")
        scope = KeyScope.ISO_APPLICATION if application else KeyScope.ISO_PICC
        self._authenticate(
            "df_raw_authenticate_iso_aes",
            key_number,
            source,
            AuthenticationProfile.ISO_AES,
            scope,
            timeout,
            (int(application),),
            prefix_before_key=True,
        )
