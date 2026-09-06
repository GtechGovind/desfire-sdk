"""ctypes lifetime and ownership boundary for the native EV3 SDK."""

from __future__ import annotations

import ctypes as ct
import os
import threading
from typing import Any, Callable, Optional, cast

from ._operations import FUNCTIONS, Operations
from .errors import DesfireError, ErrorCode, Outcome
from .raw.operations_generated import MANIFEST_SHA256
from .transport import Framing, Reader, TransportOptions

_MAX_BYTES = 16 * 1024 * 1024
_U8P = ct.POINTER(ct.c_uint8)
_READER_OWNERS_LOCK = threading.Lock()
_READER_OWNERS: dict[int, tuple[object, object]] = {}


def _claim_reader(reader: object, owner: object) -> None:
    """Prevent managed and raw channels from sharing one activated reader concurrently."""
    identity = id(reader)
    with _READER_OWNERS_LOCK:
        active = _READER_OWNERS.get(identity)
        if active is not None and active[0] is reader:
            raise DesfireError(
                ErrorCode.BUSY,
                "Reader already belongs to an open card or raw channel",
                Outcome.NOT_SENT,
            )
        _READER_OWNERS[identity] = (reader, owner)


def _release_reader(reader: object, owner: object) -> None:
    """Release a reader claim only after native callback ownership has ended."""
    identity = id(reader)
    with _READER_OWNERS_LOCK:
        active = _READER_OWNERS.get(identity)
        if active is not None and active[0] is reader and active[1] is owner:
            del _READER_OWNERS[identity]


class _Error(ct.Structure):
    """Exact fixed-layout df_error storage owned by one Python invocation."""

    _fields_ = [
        ("code", ct.c_uint32),
        ("outcome", ct.c_uint32),
        ("device_status", ct.c_uint16),
        ("message", ct.c_char * 246),
    ]


_Exchange = ct.CFUNCTYPE(
    ct.c_int32,
    ct.c_void_p,
    _U8P,
    ct.c_size_t,
    _U8P,
    ct.c_size_t,
    ct.POINTER(ct.c_size_t),
    ct.c_uint32,
    ct.POINTER(_Error),
)
_Cancel = ct.CFUNCTYPE(None, ct.c_void_p)
_Reset = ct.CFUNCTYPE(ct.c_int32, ct.c_void_p, ct.POINTER(_Error))
_Retain = ct.CFUNCTYPE(None, ct.c_void_p)
_Release = ct.CFUNCTYPE(None, ct.c_void_p)


class _Transport(ct.Structure):
    """Exact df_transport layout; its callback owners outlive all native calls."""

    _fields_ = [
        ("struct_size", ct.c_uint32),
        ("abi_version", ct.c_uint32),
        ("framing", ct.c_uint32),
        ("max_transmit", ct.c_uint32),
        ("max_receive", ct.c_uint32),
        ("max_native_frame", ct.c_uint32),
        ("context", ct.c_void_p),
        ("exchange", _Exchange),
        ("cancel", _Cancel),
        ("reset", _Reset),
        ("retain", _Retain),
        ("release", _Release),
        ("reserved", ct.c_uint64 * 8),
    ]


class _AuthenticationInfo(ct.Structure):
    """Exact versioned output written by successful EV2 authentication."""

    _fields_ = [
        ("struct_size", ct.c_uint32),
        ("abi_version", ct.c_uint32),
        ("transaction_identifier", ct.c_uint8 * 4),
        ("picc_capabilities", ct.c_uint8 * 6),
        ("pcd_capabilities", ct.c_uint8 * 6),
        ("reserved", ct.c_uint64 * 8),
    ]


class _DelegatedApplicationInfo(ct.Structure):
    """Exact versioned output for a delegated application slot query."""

    _fields_ = [
        ("struct_size", ct.c_uint32),
        ("abi_version", ct.c_uint32),
        ("slot_version", ct.c_uint32),
        ("quota_limit", ct.c_uint32),
        ("free_blocks", ct.c_uint32),
        ("application_id", ct.c_uint32),
        ("reserved", ct.c_uint64 * 8),
    ]


class _PiccConfiguration(ct.Structure):
    """Exact ABI-v1 input for documented PICC option-zero flags."""

    _fields_ = [
        ("struct_size", ct.c_uint32),
        ("abi_version", ct.c_uint32),
        ("disable_format", ct.c_uint32),
        ("random_identifier", ct.c_uint32),
        ("proximity_check_mandatory", ct.c_uint32),
        ("virtual_card_authentication_mandatory", ct.c_uint32),
        ("error_code_binding", ct.c_uint32),
        ("random_identifier_configuration", ct.c_uint32),
        ("four_byte_nuid_configuration", ct.c_uint32),
        ("reserved", ct.c_uint64 * 8),
    ]


class _TransactionOperation(ct.Structure):
    """Exact ABI-v1 transaction mutation descriptor."""

    _fields_ = [
        ("struct_size", ct.c_uint32),
        ("abi_version", ct.c_uint32),
        ("kind", ct.c_uint32),
        ("file", ct.c_uint32),
        ("communication", ct.c_uint32),
        ("offset", ct.c_uint32),
        ("record", ct.c_uint32),
        ("amount", ct.c_uint32),
        ("data", _U8P),
        ("data_size", ct.c_size_t),
        ("reserved", ct.c_uint64 * 8),
    ]


class _NativeRequest(ct.Structure):
    """Exact ABI-v1 raw native logical-request descriptor."""

    _fields_ = [
        ("struct_size", ct.c_uint32),
        ("abi_version", ct.c_uint32),
        ("framing", ct.c_uint32),
        ("command", ct.c_uint32),
        ("data", _U8P),
        ("data_size", ct.c_size_t),
        ("maximum_response", ct.c_size_t),
        ("first_frame_data_size", ct.c_size_t),
        ("flags", ct.c_uint32),
        ("reserved32", ct.c_uint32),
        ("reserved", ct.c_uint64 * 8),
    ]


class _NativeSecureRequest(ct.Structure):
    """Exact ABI-v1 explicit secure-native descriptor."""

    _fields_ = [
        ("struct_size", ct.c_uint32),
        ("abi_version", ct.c_uint32),
        ("profile", ct.c_uint32),
        ("command", ct.c_uint32),
        ("header", _U8P),
        ("header_size", ct.c_size_t),
        ("data", _U8P),
        ("data_size", ct.c_size_t),
        ("request_communication", ct.c_uint32),
        ("response_communication", ct.c_uint32),
        ("minimum_response", ct.c_size_t),
        ("maximum_response", ct.c_size_t),
        ("first_frame_data_size", ct.c_size_t),
        ("flags", ct.c_uint32),
        ("invalidates_session", ct.c_uint32),
        ("reserved", ct.c_uint64 * 8),
    ]


class _IsoApdu(ct.Structure):
    """Exact ABI-v1 true ISO APDU descriptor."""

    _fields_ = [
        ("struct_size", ct.c_uint32),
        ("abi_version", ct.c_uint32),
        ("cla", ct.c_uint32),
        ("ins", ct.c_uint32),
        ("p1", ct.c_uint32),
        ("p2", ct.c_uint32),
        ("data", _U8P),
        ("data_size", ct.c_size_t),
        ("has_le", ct.c_uint32),
        ("le", ct.c_uint32),
        ("length_encoding", ct.c_uint32),
        ("correct_length", ct.c_uint32),
        ("maximum_response", ct.c_size_t),
        ("maximum_frames", ct.c_size_t),
        ("reserved", ct.c_uint64 * 8),
    ]


class _DelegatedApplicationConfiguration(ct.Structure):
    """Exact ABI-v1 input authenticated by delegated offline utilities."""

    _fields_ = [
        ("struct_size", ct.c_uint32),
        ("abi_version", ct.c_uint32),
        ("application_id", ct.c_uint32),
        ("key_settings", ct.c_uint32),
        ("number_of_keys", ct.c_uint32),
        ("slot", ct.c_uint32),
        ("slot_version", ct.c_uint32),
        ("quota_limit", ct.c_uint32),
        ("iso_file_identifiers", ct.c_uint32),
        ("key_settings3", ct.c_int32),
        ("iso_id", ct.c_int32),
        ("df_name", _U8P),
        ("df_name_size", ct.c_size_t),
        ("has_key_sets", ct.c_uint32),
        ("active_key_set_version", ct.c_uint32),
        ("number_of_key_sets", ct.c_uint32),
        ("maximum_key_size", ct.c_uint32),
        ("key_set_settings", ct.c_uint32),
        ("reserved", ct.c_uint64 * 8),
    ]


def _integer(value: Any, minimum: int, maximum: int, name: str) -> int:
    """Reject narrowing or floating-point conversion before any call can reach a card."""
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum or value > maximum:
        raise ValueError(f"{name} must be an integer from {minimum} through {maximum}")
    return int(value)


def _check(status: int, error: _Error) -> None:
    """Raise per-call native evidence without shared last-error state."""
    if status == 0:
        return
    try:
        code = ErrorCode(status)
        outcome = Outcome(error.outcome)
    except ValueError:
        raise DesfireError(
            ErrorCode.INTERNAL,
            "Native ABI returned invalid error evidence",
        ) from None
    message = bytes(error.message).decode("utf-8", errors="replace") or "Native operation failed"
    raise DesfireError(code, message, outcome, error.device_status)


def _callback_failure(destination: Any, failure: BaseException) -> int:
    """Contain Python exceptions inside callbacks and retain only explicit delivery evidence."""
    code = ErrorCode.TRANSPORT
    outcome = Outcome.UNKNOWN
    device_status = 0
    if isinstance(failure, DesfireError):
        try:
            code = ErrorCode(failure.code)
            outcome = Outcome(failure.outcome)
            device_status = _integer(failure.device_status, 0, 0xFFFF, "device_status")
        except (ValueError, TypeError):
            code = ErrorCode.TRANSPORT
            outcome = Outcome.UNKNOWN
            device_status = 0
    if destination:
        destination.contents.code = int(code)
        destination.contents.outcome = int(outcome)
        destination.contents.device_status = device_status
        destination.contents.message = b"Reader callback failed"
    return int(code)


class _Callbacks:
    """Keep Python callback thunks and their reader alive until native ownership ends."""

    def __init__(self, reader: Reader) -> None:
        """Build exception-contained callbacks without capturing the owning Card."""
        if not callable(getattr(reader, "exchange", None)):
            raise TypeError("reader.exchange must be callable")
        self.reader = reader
        self.cancel_errors = threading.local()

        def exchange(
            context: Any,
            transmit: Any,
            transmit_size: int,
            receive: Any,
            capacity: int,
            received: Any,
            timeout_ms: int,
            error: Any,
        ) -> int:
            """Perform one bounded frame exchange; never retry an exception or error."""
            del context
            received[0] = 0
            try:
                if transmit_size > _MAX_BYTES or capacity > _MAX_BYTES:
                    raise DesfireError(ErrorCode.INVALID_ARGUMENT, "Invalid native frame limits")
                request = ct.string_at(transmit, transmit_size)
                response = reader.exchange(request, timeout_ms)
                if not isinstance(response, (bytes, bytearray, memoryview)):
                    raise TypeError("reader.exchange must return a binary buffer")
                view = memoryview(response)
                if view.ndim != 1 or view.itemsize != 1 or not view.c_contiguous:
                    raise TypeError("reader.exchange must return contiguous byte-oriented data")
                if view.nbytes > capacity:
                    raise DesfireError(
                        ErrorCode.MALFORMED_RESPONSE,
                        "Reader exceeded receive capacity",
                        Outcome.UNKNOWN,
                    )
                if view.nbytes:
                    owned = (ct.c_uint8 * view.nbytes).from_buffer_copy(view)
                    ct.memmove(receive, owned, view.nbytes)
                received[0] = view.nbytes
                return 0
            except BaseException as failure:
                return _callback_failure(error, failure)

        self.exchange = _Exchange(exchange)
        cancel_method = getattr(reader, "cancel", None)
        reset_method = getattr(reader, "reset", None)
        if cancel_method is not None and not callable(cancel_method):
            raise TypeError("reader.cancel must be callable when supplied")
        if reset_method is not None and not callable(reset_method):
            raise TypeError("reader.reset must be callable when supplied")
        cancel_callback = cast(Optional[Callable[[], None]], cancel_method)
        reset_callback = cast(Optional[Callable[[], None]], reset_method)

        def cancel(context: Any) -> None:
            """Contain cancellation exceptions, returning evidence to the Python caller."""
            del context
            try:
                if cancel_callback is not None:
                    cancel_callback()
            except BaseException:
                self.cancel_errors.failure = DesfireError(
                    ErrorCode.TRANSPORT,
                    "Reader cancellation callback failed",
                    Outcome.UNKNOWN,
                )

        def reset(context: Any, error: Any) -> int:
            """Report a reset failure without allowing a Python exception across C."""
            del context
            try:
                if reset_callback is not None:
                    reset_callback()
                return 0
            except BaseException as failure:
                return _callback_failure(error, failure)

        self.cancel = _Cancel(cancel) if cancel_method is not None else _Cancel()
        self.reset = _Reset(reset) if reset_method is not None else _Reset()


class _Library:
    """Explicitly loaded ABI with fixed argument widths, pointer ownership, and version."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        """Load the caller-selected native library and require ABI version 1."""
        self.native = ct.CDLL(os.path.abspath(os.fspath(path)))
        self.native.df_abi_version.argtypes = []
        self.native.df_abi_version.restype = ct.c_uint32
        if self.native.df_abi_version() != 1:
            raise RuntimeError("The native DESFire library does not implement ABI version 1")
        self.native.df_manifest_sha256.argtypes = []
        self.native.df_manifest_sha256.restype = ct.c_char_p
        manifest = self.native.df_manifest_sha256()
        if manifest is None or manifest.decode("ascii", errors="replace") != MANIFEST_SHA256:
            raise RuntimeError("The native DESFire library and Python operation manifest differ")
        self._bind("df_open", [ct.POINTER(_Transport), ct.POINTER(ct.c_uint64)])
        for name in ("df_close", "df_reset", "df_cancel", "df_notify_state_change"):
            self._bind(name, [ct.c_uint64])
        self.native.df_buffer_size.argtypes = [ct.c_void_p]
        self.native.df_buffer_size.restype = ct.c_size_t
        self.native.df_buffer_data.argtypes = [ct.c_void_p]
        self.native.df_buffer_data.restype = _U8P
        self.native.df_buffer_free.argtypes = [ct.c_void_p]
        self.native.df_buffer_free.restype = None
        for name, (arguments, output) in FUNCTIONS.items():
            types: list[Any] = [ct.c_uint64]
            for _, kind in arguments:
                if kind == "bytes":
                    types.extend([_U8P, ct.c_size_t])
                else:
                    types.append(ct.c_uint32 if kind == "u32" else ct.c_int32)
            if output != "void":
                value_type = {
                    "bytes": ct.c_void_p,
                    "u32": ct.c_uint32,
                    "i32": ct.c_int32,
                    "authentication_info": _AuthenticationInfo,
                    "delegated_application_info": _DelegatedApplicationInfo,
                }[output]
                types.append(ct.POINTER(value_type))
            self._bind(name, types)
        self._bind(
            "df_authenticate_standard_aes",
            [ct.c_uint64, ct.c_uint32, _U8P, ct.c_size_t, ct.c_uint32],
        )
        self._bind(
            "df_authenticate_ev2_first_aes",
            [
                ct.c_uint64,
                ct.c_uint32,
                _U8P,
                ct.c_size_t,
                ct.c_uint32,
                ct.POINTER(_AuthenticationInfo),
            ],
        )
        self._bind(
            "df_authenticate_ev2_first_aes_with_capabilities",
            [
                ct.c_uint64,
                ct.c_uint32,
                _U8P,
                ct.c_size_t,
                _U8P,
                ct.c_size_t,
                ct.c_uint32,
                ct.POINTER(_AuthenticationInfo),
            ],
        )
        self._bind(
            "df_authenticate_ev2_non_first_aes",
            [
                ct.c_uint64,
                ct.c_uint32,
                _U8P,
                ct.c_size_t,
                ct.c_uint32,
                ct.POINTER(_AuthenticationInfo),
            ],
        )
        self._bind(
            "df_authenticate_iso_aes",
            [ct.c_uint64, ct.c_uint32, ct.c_uint32, _U8P, ct.c_size_t, ct.c_uint32],
        )
        self._bind(
            "df_set_picc_configuration",
            [ct.c_uint64, ct.POINTER(_PiccConfiguration), ct.c_uint32],
        )
        self._bind(
            "df_execute_transaction",
            [
                ct.c_uint64,
                ct.POINTER(_TransactionOperation),
                ct.c_size_t,
                ct.c_uint32,
                ct.c_uint32,
                ct.POINTER(ct.c_void_p),
            ],
        )
        self._bind("df_raw_open", [ct.POINTER(_Transport), ct.POINTER(ct.c_uint64)])
        for name in ("df_raw_close", "df_raw_reset", "df_raw_cancel", "df_raw_notify_state_change"):
            self._bind(name, [ct.c_uint64])
        self._bind(
            "df_raw_native_frame",
            [
                ct.c_uint64,
                ct.c_uint32,
                ct.c_uint32,
                _U8P,
                ct.c_size_t,
                ct.c_uint32,
                ct.POINTER(ct.c_uint32),
                ct.POINTER(ct.c_void_p),
            ],
        )
        self._bind(
            "df_raw_native_exchange",
            [
                ct.c_uint64,
                ct.POINTER(_NativeRequest),
                ct.c_uint32,
                ct.POINTER(ct.c_uint32),
                ct.POINTER(ct.c_void_p),
            ],
        )
        self._bind(
            "df_raw_iso_exchange",
            [
                ct.c_uint64,
                ct.POINTER(_IsoApdu),
                ct.c_uint32,
                ct.POINTER(ct.c_uint32),
                ct.POINTER(ct.c_void_p),
            ],
        )
        self._bind(
            "df_raw_iso_secure_exchange",
            [
                ct.c_uint64,
                ct.POINTER(_IsoApdu),
                ct.c_uint32,
                ct.POINTER(ct.c_uint32),
                ct.POINTER(ct.c_void_p),
            ],
        )
        self._bind(
            "df_raw_native_secure_exchange",
            [ct.c_uint64, ct.POINTER(_NativeSecureRequest), ct.c_uint32, ct.POINTER(ct.c_void_p)],
        )
        self._bind(
            "df_raw_authenticate_standard_aes",
            [ct.c_uint64, ct.c_uint32, _U8P, ct.c_size_t, ct.c_uint32],
        )
        self._bind(
            "df_raw_authenticate_ev2_first_aes",
            [
                ct.c_uint64,
                ct.c_uint32,
                _U8P,
                ct.c_size_t,
                _U8P,
                ct.c_size_t,
                ct.c_uint32,
                ct.POINTER(_AuthenticationInfo),
            ],
        )
        self._bind(
            "df_raw_authenticate_ev2_non_first_aes",
            [
                ct.c_uint64,
                ct.c_uint32,
                _U8P,
                ct.c_size_t,
                ct.c_uint32,
                ct.POINTER(_AuthenticationInfo),
            ],
        )
        self._bind(
            "df_raw_authenticate_iso_aes",
            [ct.c_uint64, ct.c_uint32, ct.c_uint32, _U8P, ct.c_size_t, ct.c_uint32],
        )
        self._bind(
            "df_offline_derive_nxp_aes128",
            [_U8P, ct.c_size_t, _U8P, ct.c_size_t, ct.POINTER(ct.c_void_p)],
        )
        self._bind(
            "df_offline_calculate_transaction_mac_aes",
            [
                _U8P,
                ct.c_size_t,
                ct.c_uint32,
                _U8P,
                ct.c_size_t,
                _U8P,
                ct.c_size_t,
                ct.POINTER(ct.c_void_p),
            ],
        )
        self._bind(
            "df_offline_encrypt_delegated_default_key_aes",
            [_U8P, ct.c_size_t, _U8P, ct.c_size_t, ct.c_uint32, ct.POINTER(ct.c_void_p)],
        )
        self._bind(
            "df_offline_calculate_delegated_application_mac_aes",
            [
                _U8P,
                ct.c_size_t,
                ct.POINTER(_DelegatedApplicationConfiguration),
                _U8P,
                ct.c_size_t,
                ct.POINTER(ct.c_void_p),
            ],
        )
        self._bind(
            "df_offline_calculate_delegated_application_delete_mac_aes",
            [_U8P, ct.c_size_t, ct.c_uint32, ct.POINTER(ct.c_void_p)],
        )
        self._bind(
            "df_offline_calculate_delegated_configuration_mac_aes",
            [_U8P, ct.c_size_t, _U8P, ct.c_size_t, _U8P, ct.c_size_t, ct.POINTER(ct.c_void_p)],
        )
        self._bind(
            "df_offline_calculate_mfc_license_mac_aes",
            [_U8P, ct.c_size_t, _U8P, ct.c_size_t, _U8P, ct.c_size_t, ct.POINTER(ct.c_void_p)],
        )
        self._bind(
            "df_offline_derive_transaction_mac_keys_aes",
            [_U8P, ct.c_size_t, ct.c_uint32, _U8P, ct.c_size_t, ct.POINTER(ct.c_void_p)],
        )
        self._bind(
            "df_offline_calculate_transaction_mac_session_aes",
            [_U8P, ct.c_size_t, _U8P, ct.c_size_t, ct.POINTER(ct.c_void_p)],
        )
        self._bind(
            "df_offline_verify_transaction_mac_aes",
            [
                _U8P,
                ct.c_size_t,
                ct.c_uint32,
                _U8P,
                ct.c_size_t,
                _U8P,
                ct.c_size_t,
                _U8P,
                ct.c_size_t,
                ct.POINTER(ct.c_uint32),
            ],
        )
        self._bind(
            "df_offline_decrypt_transaction_reader_id_aes",
            [_U8P, ct.c_size_t, _U8P, ct.c_size_t, ct.POINTER(ct.c_void_p)],
        )
        self._bind(
            "df_offline_verify_originality_uid_signature",
            [
                ct.c_char_p,
                _U8P,
                ct.c_size_t,
                _U8P,
                ct.c_size_t,
                _U8P,
                ct.c_size_t,
                ct.POINTER(ct.c_uint32),
            ],
        )

    def _bind(self, name: str, types: list[Any]) -> None:
        """Declare a fallible C function, including its call-owned error pointer."""
        function = getattr(self.native, name)
        function.argtypes = [*types, ct.POINTER(_Error)]
        function.restype = ct.c_int32


class Card(Operations):
    """Own one native EV3 connection and callback lifetime; use as a context manager.

    Native logical commands are serialized, and a concurrent/reentrant command reports
    BUSY. Cancellation bypasses that command lock. Failed mutations are never retried.
    The host owns reader setup, polling, disconnect detection, and key persistence.
    """

    def __init__(
        self,
        library: str | os.PathLike[str],
        reader: Reader,
        options: TransportOptions = TransportOptions(),
    ) -> None:
        """Open a connection without card I/O, retaining reader callbacks until close."""
        self._handle = 0
        self._admission = threading.Condition()
        self._next_ticket = 0
        self._serving_ticket = 0
        self._active_thread: int | None = None
        self._closing = False
        self._reader_claim = object()
        _claim_reader(reader, self._reader_claim)
        framing = Framing(options.framing)
        maximum_transmit = _integer(options.max_transmit, 6, _MAX_BYTES, "max_transmit")
        maximum_receive = _integer(options.max_receive, 2, _MAX_BYTES, "max_receive")
        maximum_frame = _integer(options.max_native_frame, 2, maximum_transmit, "max_native_frame")
        try:
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
            status = self._library.native.df_open(
                ct.byref(self._transport),
                ct.byref(handle),
                ct.byref(error),
            )
            _check(status, error)
            self._handle = handle.value
        except BaseException:
            _release_reader(reader, self._reader_claim)
            raise

    @property
    def closed(self) -> bool:
        """Return whether this wrapper has successfully released native ownership."""
        return self._handle == 0

    def __enter__(self) -> "Card":
        """Borrow this live connection for a with-statement."""
        self._require_open()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        """Close the connection when leaving a with-statement, including failure paths."""
        self.close()

    def __del__(self) -> None:
        """Attempt local handle cleanup; explicit close is needed to observe cleanup failures."""
        try:
            self.close()
        except BaseException:
            pass

    def _require_open(self) -> int:
        """Reject a closed wrapper locally, before any native operation can transmit."""
        with self._admission:
            if not self._handle or self._closing:
                raise DesfireError(
                    ErrorCode.STALE_HANDLE,
                    "Card is closing or closed",
                    Outcome.NOT_SENT,
                )
            return self._handle

    def _enter_operation(self) -> int:
        """Admit one FIFO operation, rejecting same-card callback reentry before waiting."""
        thread = threading.get_ident()
        with self._admission:
            if not self._handle or self._closing:
                raise DesfireError(
                    ErrorCode.STALE_HANDLE,
                    "Card is closing or closed",
                    Outcome.NOT_SENT,
                )
            if self._active_thread == thread:
                raise DesfireError(
                    ErrorCode.BUSY,
                    "Reader callbacks cannot reenter their card",
                    Outcome.NOT_SENT,
                )
            ticket = self._next_ticket
            self._next_ticket += 1
            while ticket != self._serving_ticket:
                self._admission.wait()
            self._active_thread = thread
            return self._handle

    def _leave_operation(self) -> None:
        """Advance the FIFO after native ownership and temporary key copies are released."""
        with self._admission:
            self._active_thread = None
            self._serving_ticket += 1
            self._admission.notify_all()

    def close(self) -> None:
        """Reject new work, drain admitted FIFO operations, and release ownership once."""
        thread = threading.get_ident()
        with self._admission:
            if not self._handle:
                return
            if self._active_thread == thread:
                raise DesfireError(
                    ErrorCode.BUSY,
                    "Reader callbacks cannot close their card",
                    Outcome.NOT_SENT,
                )
            if self._closing:
                while self._closing and self._handle:
                    self._admission.wait()
                if not self._handle:
                    return
            self._closing = True
            while self._serving_ticket != self._next_ticket or self._active_thread is not None:
                self._admission.wait()
            handle = self._handle
        error = _Error()
        try:
            status = self._library.native.df_close(handle, ct.byref(error))
            _check(status, error)
        except BaseException:
            with self._admission:
                self._closing = False
                self._admission.notify_all()
            raise
        with self._admission:
            self._handle = 0
            self._closing = False
            self._admission.notify_all()
        _release_reader(self._callbacks.reader, self._reader_claim)

    def reset(self) -> None:
        """Use the host reset callback and invalidate native selection/session state."""
        self._lifecycle("df_reset")

    def notify_state_change(self) -> None:
        """Invalidate session state after host-observed removal, reconnect, or reader reset."""
        self._lifecycle("df_notify_state_change")

    def cancel(self) -> None:
        """Cancel concurrently with an active command without acquiring its operation lock."""
        self._callbacks.cancel_errors.failure = None
        self._lifecycle("df_cancel", allow_closing=True)
        failure = self._callbacks.cancel_errors.failure
        if failure is not None:
            raise failure

    def _lifecycle(self, name: str, allow_closing: bool = False) -> None:
        """Invoke a lifecycle operation with its own handle and error storage."""
        if allow_closing:
            with self._admission:
                if not self._handle:
                    raise DesfireError(ErrorCode.STALE_HANDLE, "Card is closed", Outcome.NOT_SENT)
                handle = self._handle
        else:
            handle = self._require_open()
        error = _Error()
        status = getattr(self._library.native, name)(handle, ct.byref(error))
        _check(status, error)

    def _invoke(self, name: str, arguments: tuple[Any, ...]) -> Any:
        """Marshal one typed call and always free output buffers and wipe temporary inputs."""
        parameters, output = FUNCTIONS[name]
        if len(parameters) != len(arguments):
            raise TypeError("Native binding argument count mismatch")
        handle = self._enter_operation()
        try:
            return self._invoke_admitted(handle, name, arguments)
        finally:
            self._leave_operation()

    def _invoke_admitted(self, handle: int, name: str, arguments: tuple[Any, ...]) -> Any:
        """Marshal one call after the caller has acquired this Card's FIFO admission."""
        parameters, output = FUNCTIONS[name]
        converted: list[Any] = [handle]
        temporary: list[Any] = []
        result: Any = None
        try:
            for index, ((argument_name, kind), value) in enumerate(zip(parameters, arguments)):
                if kind == "bytes":
                    if not isinstance(value, (bytes, bytearray, memoryview)):
                        raise TypeError(
                            "Native byte arguments require bytes, bytearray, or memoryview",
                        )
                    view = memoryview(value)
                    if (
                        view.ndim != 1
                        or view.itemsize != 1
                        or not view.c_contiguous
                        or view.nbytes > _MAX_BYTES
                    ):
                        raise ValueError(
                            "Native byte arguments must be contiguous and at most 16 MiB",
                        )
                    buffer = (ct.c_uint8 * view.nbytes).from_buffer_copy(view)
                    temporary.append(buffer)
                    converted.extend([buffer, view.nbytes])
                elif kind == "u32":
                    minimum = 1 if argument_name == "timeout_ms" else 0
                    converted.append(_integer(value, minimum, 0xFFFFFFFF, argument_name))
                else:
                    converted.append(_integer(value, -0x80000000, 0x7FFFFFFF, argument_name))
            if output != "void":
                value_type: Any = {
                    "bytes": ct.c_void_p,
                    "u32": ct.c_uint32,
                    "i32": ct.c_int32,
                    "authentication_info": _AuthenticationInfo,
                    "delegated_application_info": _DelegatedApplicationInfo,
                }[output]
                result = value_type()
                if output in {"authentication_info", "delegated_application_info"}:
                    result.struct_size = ct.sizeof(value_type)
                    result.abi_version = 1
                converted.append(ct.byref(result))
            error = _Error()
            status = getattr(self._library.native, name)(*converted, ct.byref(error))
            _check(status, error)
            if output == "void":
                return None
            if output != "bytes":
                if output in {"u32", "i32"}:
                    return result.value
                if output == "authentication_info":
                    from .models import AuthenticationInfo

                    return AuthenticationInfo(
                        bytes(result.transaction_identifier),
                        bytes(result.picc_capabilities),
                        bytes(result.pcd_capabilities),
                    )
                from .models import ApplicationId, DelegatedApplicationInfo

                return DelegatedApplicationInfo(
                    result.slot_version,
                    result.quota_limit,
                    result.free_blocks,
                    ApplicationId(result.application_id),
                )
            if not result.value:
                raise DesfireError(ErrorCode.INTERNAL, "Native command returned no owned buffer")
            size = self._library.native.df_buffer_size(result)
            data = self._library.native.df_buffer_data(result)
            if size > _MAX_BYTES or (size and not data):
                raise DesfireError(ErrorCode.INTERNAL, "Native output buffer is invalid")
            return ct.string_at(data, size)
        finally:
            if output == "bytes" and result is not None and result.value:
                self._library.native.df_buffer_free(result)
            for buffer in temporary:
                ct.memset(ct.addressof(buffer), 0, ct.sizeof(buffer))

    def _set_picc_configuration(self, configuration: Any, timeout_ms: int) -> None:
        """Marshal one named PICC configuration under normal FIFO admission."""
        timeout = _integer(timeout_ms, 1, 0xFFFFFFFF, "timeout_ms")
        descriptor = _PiccConfiguration(
            ct.sizeof(_PiccConfiguration),
            1,
            int(configuration.disable_format),
            int(configuration.random_identifier),
            int(configuration.proximity_check_mandatory),
            int(configuration.virtual_card_authentication_mandatory),
            int(configuration.error_code_binding),
            int(configuration.random_identifier_configuration),
            int(configuration.four_byte_nuid_configuration),
            (ct.c_uint64 * 8)(),
        )
        handle = self._enter_operation()
        try:
            error = _Error()
            status = self._library.native.df_set_picc_configuration(
                handle,
                ct.byref(descriptor),
                timeout,
                ct.byref(error),
            )
            _check(status, error)
        finally:
            self._leave_operation()

    def _execute_transaction(
        self,
        operations: tuple[Any, ...],
        return_mac: bool,
        timeout_ms: int,
    ) -> bytes:
        """Marshal a bounded immutable transaction plan and copy its commit receipt."""
        if not operations or len(operations) > 128:
            raise ValueError("a transaction requires one through 128 operations")
        if not isinstance(return_mac, bool):
            raise TypeError("return_mac must be a bool")
        timeout = _integer(timeout_ms, 1, 0xFFFFFFFF, "timeout_ms")
        descriptors = (_TransactionOperation * len(operations))()
        data_owners: list[Any] = []
        for index, operation in enumerate(operations):
            data = operation.data
            owner = (ct.c_uint8 * len(data)).from_buffer_copy(data)
            data_owners.append(owner)
            descriptors[index] = _TransactionOperation(
                ct.sizeof(_TransactionOperation),
                1,
                int(operation.kind),
                operation.file.value,
                int(operation.communication),
                operation.offset.value,
                operation.record,
                operation.amount,
                owner,
                len(data),
                (ct.c_uint64 * 8)(),
            )
        handle = self._enter_operation()
        result = ct.c_void_p()
        try:
            error = _Error()
            status = self._library.native.df_execute_transaction(
                handle,
                descriptors,
                len(operations),
                int(return_mac),
                timeout,
                ct.byref(result),
                ct.byref(error),
            )
            _check(status, error)
            if not result.value:
                raise DesfireError(ErrorCode.INTERNAL, "Native transaction returned no receipt")
            size = self._library.native.df_buffer_size(result)
            data = self._library.native.df_buffer_data(result)
            if size > _MAX_BYTES or (size and not data):
                raise DesfireError(ErrorCode.INTERNAL, "Native transaction receipt is invalid")
            return ct.string_at(data, size)
        finally:
            if result.value:
                self._library.native.df_buffer_free(result)
            for owner in data_owners:
                ct.memset(ct.addressof(owner), 0, ct.sizeof(owner))
            self._leave_operation()
