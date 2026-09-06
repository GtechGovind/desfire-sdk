"""Host integration checks against the real C ABI with deterministic reader callbacks."""

from __future__ import annotations

import gc
import os
import threading
import unittest

from desfire_ev3 import (
    Aes128Key,
    AuthenticationProfile,
    Card,
    DerivationContext,
    DesfireError,
    Direct,
    ErrorCode,
    Framing,
    KeyNumber,
    KeyPurpose,
    KeyRequest,
    Outcome,
    Provider,
    TransportOptions,
)
from desfire_ev3.raw import IsoApdu, NativeRequest, RawCard


class Replay:
    """Consume an exact finite sequence of externally specified reader frames."""

    def __init__(self, frames: list[tuple[str, str | BaseException]]) -> None:
        """Retain non-secret hexadecimal fixtures and the current frame position."""
        self.frames = list(frames)
        self.calls = 0

    def exchange(self, request: bytes, timeout_ms: int) -> bytes:
        """Verify bytes and timeout before returning exactly one response or failure."""
        self.calls += 1
        if not self.frames:
            raise AssertionError("Unexpected reader exchange")
        expected, response = self.frames.pop(0)
        if request != bytes.fromhex(expected) or timeout_ms <= 0:
            raise AssertionError("Reader frame or timeout differs from fixture")
        if isinstance(response, BaseException):
            raise response
        return bytes.fromhex(response)


@unittest.skipUnless(os.environ.get("DESFIRE_LIBRARY"), "Set DESFIRE_LIBRARY to the built C ABI")
class BindingTests(unittest.TestCase):
    """Validate ctypes argument widths, callback failures, lifecycle, and owned outputs."""

    def connect(self, reader: object, framing: Framing = Framing.ISO_WRAPPED) -> Card:
        """Open the explicit test library with a retained host reader."""
        return Card(os.environ["DESFIRE_LIBRARY"], reader, TransportOptions(framing=framing))

    def connect_raw(self, reader: object, framing: Framing = Framing.ISO_WRAPPED) -> RawCard:
        """Open an independent expert channel for exact-status tests."""
        return RawCard(
            os.environ["DESFIRE_LIBRARY"],
            reader,
            TransportOptions(framing=framing),
        )

    def test_wrapped_version_chaining_and_context_close(self) -> None:
        """GetVersion crosses Python/C callbacks three times and returns one owned payload."""
        first = "04010112001805"
        second = "04010203040506"
        final = "0401020304050601020304050124"
        reader = Replay(
            [
                ("9060000000", first + "91af"),
                ("90af000000", second + "91af"),
                ("90af000000", final + "9100"),
            ]
        )
        with self.connect(reader) as card:
            payload = card.get_version()
            self.assertEqual(payload, bytes.fromhex(first + second + final))
        self.assertTrue(card.closed)
        self.assertEqual(reader.calls, 3)
        with self.assertRaises(DesfireError) as failure:
            card.get_version()
        self.assertEqual(failure.exception.code, ErrorCode.STALE_HANDLE)
        self.assertEqual(failure.exception.outcome, Outcome.NOT_SENT)
        card.close()

    def test_native_framing_scalar_and_owned_array(self) -> None:
        """Native status precedes data and scalar output preserves little-endian decoding."""
        reader = Replay([("6e", "00341200"), ("6f", "0000031f")])
        with self.connect(reader, Framing.NATIVE) as card:
            self.assertEqual(card.free_memory(), 0x1234)
            self.assertEqual(card.file_ids(), bytes.fromhex("00031f"))
        self.assertEqual(reader.frames, [])

    def test_callback_explicit_failure_evidence(self) -> None:
        """The C ABI retains a known unsent timeout without retrying."""
        timeout = DesfireError(ErrorCode.TIMEOUT, "test timeout", Outcome.NOT_SENT, 0xBEEF)
        reader = Replay([("906e000000", timeout)])
        with self.connect(reader) as card:
            with self.assertRaises(DesfireError) as failure:
                card.free_memory()
            self.assertEqual(failure.exception.code, ErrorCode.TIMEOUT)
            self.assertEqual(failure.exception.outcome, Outcome.NOT_SENT)
            self.assertEqual(failure.exception.device_status, 0xBEEF)
        self.assertEqual(reader.calls, 1)

    def test_unexpected_python_exception_has_unknown_delivery(self) -> None:
        """Ordinary Python exceptions never escape ctypes or imply a safely unsent command."""
        reader = Replay([("906e000000", RuntimeError("private implementation diagnostic"))])
        with self.connect(reader) as card:
            with self.assertRaises(DesfireError) as failure:
                card.free_memory()
            self.assertEqual(failure.exception.code, ErrorCode.TRANSPORT)
            self.assertEqual(failure.exception.outcome, Outcome.UNKNOWN)
            self.assertNotIn("private implementation", str(failure.exception))
        self.assertEqual(reader.calls, 1)

    def test_pre_io_narrowing_and_timeout_validation(self) -> None:
        """Python rejects negative, overflowing, and non-integral values before C narrowing."""
        reader = Replay([])
        with self.connect(reader) as card:
            for invalid in (-1, 1 << 32, 1.25, "1"):
                with self.assertRaises(ValueError):
                    card.select_application(invalid)
            for invalid in (0, -1, 1 << 32):
                with self.assertRaises(ValueError):
                    card.get_version(timeout_ms=invalid)
            with self.assertRaises(DesfireError) as failure:
                card.select_application(1 << 24)
            self.assertEqual(failure.exception.code, ErrorCode.INVALID_ARGUMENT)
        self.assertEqual(reader.calls, 0)

    def test_key_buffer_input_and_local_key_validation(self) -> None:
        """Temporary byte buffers keep caller-owned keys intact, and invalid keys never send."""
        key = bytearray(15)
        reader = Replay([])
        with self.connect(reader) as card:
            with self.assertRaises(ValueError):
                card.authenticate_standard_aes(KeyNumber(0), Direct(Aes128Key(key)))
            self.assertEqual(key, bytearray(15))
            with self.assertRaises(TypeError):
                card.authenticate_standard_aes(KeyNumber(0), "not bytes")
            with self.assertRaises(ValueError):
                Aes128Key(memoryview(bytearray(32))[::2])
        self.assertEqual(reader.calls, 0)

    def test_provider_failure_inside_card_queue_performs_zero_io(self) -> None:
        """Provider exceptions are redacted as unsent failures before authentication frames."""

        class FailingProvider:
            """Count one lookup and expose a private diagnostic that must not escape."""

            calls = 0

            def resolve(self, request: KeyRequest) -> Aes128Key:
                """Fail deterministically after observing the scoped request."""
                self.calls += 1
                raise RuntimeError("private provider backend")

        reader = Replay([])
        provider = FailingProvider()
        request = KeyRequest(
            b"application-key",
            DerivationContext(KeyPurpose.AUTHENTICATION, KeyNumber(2)),
            AuthenticationProfile.STANDARD_AES,
        )
        with self.connect(reader) as card:
            with self.assertRaises(DesfireError) as failure:
                card.authenticate_standard_aes(KeyNumber(2), Provider(request, provider))
            self.assertEqual(failure.exception.outcome, Outcome.NOT_SENT)
            self.assertNotIn("private", str(failure.exception))
        self.assertEqual(provider.calls, 1)
        self.assertEqual(reader.calls, 0)

    def test_plain_write_frame_and_empty_buffer_result(self) -> None:
        """A typed write forwards bytes once and ISO SELECT returns an owned empty result."""
        reader = Replay(
            [
                ("903d00000a0200000003000010203000", "9100"),
                ("00a4000c02ef01", "9000"),
            ]
        )
        with self.connect(reader) as card:
            card.write_data(2, 0, bytearray.fromhex("102030"), 0)
            self.assertEqual(card.iso_select_file(0xEF01, 0, 0x0C), b"")
        self.assertEqual(reader.calls, 2)

    def test_actual_iso_binary_and_status_evidence(self) -> None:
        """CLA 00 ISO operations use the native ISO engine and preserve rejection SW1/SW2."""
        reader = Replay(
            [
                ("00b0000003", "0102039000"),
                ("00b0000003", "6982"),
            ]
        )
        with self.connect(reader) as card:
            self.assertEqual(card.iso_read_binary(-1, 0, 3), b"\x01\x02\x03")
            with self.assertRaises(DesfireError) as failure:
                card.iso_read_binary(-1, 0, 3)
            self.assertEqual(failure.exception.device_status, 0x6982)
            self.assertEqual(failure.exception.code, ErrorCode.CARD_REJECTED)

    def test_raw_native_frame_and_logical_exchange_preserve_status(self) -> None:
        """Raw native surfaces return status bytes separately from status-free payloads."""
        reader = Replay(
            [
                ("906e000000", "112291af"),
                ("906f000000", "aabb9100"),
            ]
        )
        with self.connect_raw(reader) as card:
            frame = card.native_frame(0x6E)
            self.assertEqual((frame.data, frame.status), (b"\x11\x22", 0xAF))
            logical = card.native_exchange(NativeRequest(0x6F))
            self.assertEqual((logical.data, logical.status), (b"\xaa\xbb", 0x00))

    def test_raw_iso_warning_data_is_not_discarded(self) -> None:
        """True ISO raw exchange exposes warning data and the exact SW1/SW2 value."""
        reader = Replay([("00ca000000", "01026283")])
        with self.connect_raw(reader) as card:
            response = card.iso_exchange(IsoApdu(0x00, 0xCA, 0x00, 0x00, le=256))
            self.assertEqual(response.data, b"\x01\x02")
            self.assertEqual(response.status_word, 0x6283)

    def test_reader_cannot_be_shared_between_managed_and_raw_channels(self) -> None:
        """Python enforces raw/managed ownership before a second native handle is opened."""
        reader = Replay([])
        with self.connect(reader):
            with self.assertRaises(DesfireError) as failure:
                self.connect_raw(reader)
            self.assertEqual(failure.exception.code, ErrorCode.BUSY)
            self.assertEqual(failure.exception.outcome, Outcome.NOT_SENT)

    def test_oversized_callback_response(self) -> None:
        """An over-capacity callback result fails before memcpy and preserves unknown delivery."""

        class Oversized:
            """Reader fixture returning more data than the declared capacity."""

            def exchange(self, request: bytes, timeout_ms: int) -> bytes:
                """Return nine bytes to a reader connection limited to eight."""
                return bytes(9)

        with Card(
            os.environ["DESFIRE_LIBRARY"], Oversized(), TransportOptions(max_receive=8)
        ) as card:
            with self.assertRaises(DesfireError) as failure:
                card.free_memory()
            self.assertEqual(failure.exception.code, ErrorCode.MALFORMED_RESPONSE)
            self.assertEqual(failure.exception.outcome, Outcome.UNKNOWN)

    def test_reentrant_callback_fails_busy(self) -> None:
        """Callback recursion reports BUSY instead of deadlocking the original operation."""

        class Reentrant:
            """Reader fixture that attempts a second command from its exchange callback."""

            card: Card
            nested: DesfireError | None = None

            def exchange(self, request: bytes, timeout_ms: int) -> bytes:
                """Capture recursive-call evidence, then complete the original read."""
                try:
                    self.card.file_ids()
                except DesfireError as failure:
                    self.nested = failure
                return bytes.fromhex("0200009100")

        reader = Reentrant()
        with self.connect(reader) as card:
            reader.card = card
            self.assertEqual(card.free_memory(), 2)
            self.assertIsNotNone(reader.nested)
            self.assertEqual(reader.nested.code, ErrorCode.BUSY)

    def test_concurrent_cancel_and_draining_close(self) -> None:
        """Cancellation wakes active I/O while close drains already admitted work."""

        class Blocking:
            """Reader fixture whose exchange returns only after cancellation."""

            def __init__(self) -> None:
                """Create deterministic start and cancellation events."""
                self.started = threading.Event()
                self.cancelled = threading.Event()

            def exchange(self, request: bytes, timeout_ms: int) -> bytes:
                """Wait with a bounded safety deadline and return cancellation evidence."""
                self.started.set()
                self.cancelled.wait(3)
                raise DesfireError(ErrorCode.CANCELLED, "test cancellation", Outcome.UNKNOWN)

            def cancel(self) -> None:
                """Wake the blocked foreign callback without acquiring a command lock."""
                self.cancelled.set()

        reader = Blocking()
        card = self.connect(reader)
        failures: list[DesfireError] = []

        def run() -> None:
            """Capture the result from the command thread without dropping its Card reference."""
            try:
                card.free_memory()
            except DesfireError as failure:
                failures.append(failure)

        thread = threading.Thread(target=run)
        thread.start()
        close_failures: list[BaseException] = []

        def close() -> None:
            """Close from another thread while the admitted operation is still active."""
            try:
                card.close()
            except BaseException as failure:
                close_failures.append(failure)

        try:
            self.assertTrue(reader.started.wait(2))
            closing = threading.Thread(target=close)
            closing.start()
            gc.collect()
            card.cancel()
            thread.join(3)
            closing.join(3)
            self.assertFalse(thread.is_alive())
            self.assertFalse(closing.is_alive())
            self.assertEqual(len(failures), 1)
            self.assertEqual(failures[0].code, ErrorCode.CANCELLED)
            self.assertEqual(close_failures, [])
            self.assertTrue(card.closed)
        finally:
            reader.cancelled.set()
            thread.join(3)
            card.close()

    def test_reset_exception_is_contained(self) -> None:
        """A Python reset exception remains an observable C error with unknown delivery."""

        class BrokenReset(Replay):
            """Reader fixture whose optional reset method fails."""

            def reset(self) -> None:
                """Inject a reset error before any subsequent exchange."""
                raise RuntimeError("reset failed")

        with self.connect(BrokenReset([])) as card:
            with self.assertRaises(DesfireError) as failure:
                card.reset()
            self.assertEqual(failure.exception.outcome, Outcome.UNKNOWN)

    def test_cancel_exception_is_observable(self) -> None:
        """Void C cancellation callbacks still report Python-side failures to their caller."""

        class BrokenCancel(Replay):
            """Reader fixture whose optional cancellation method fails."""

            def cancel(self) -> None:
                """Inject a cancellation failure while preserving callback exception containment."""
                raise RuntimeError("cancel failed")

        with self.connect(BrokenCancel([])) as card:
            with self.assertRaises(DesfireError) as failure:
                card.cancel()
            self.assertEqual(failure.exception.code, ErrorCode.TRANSPORT)


if __name__ == "__main__":
    unittest.main()
