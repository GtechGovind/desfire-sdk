"""AsyncCard queue, dedicated-thread, cancellation, and provider behavior."""

from __future__ import annotations

import asyncio
import os
import threading
import unittest

from desfire_ev3 import (
    Aes128Key,
    AsyncCard,
    AsyncProvider,
    AuthenticationProfile,
    DerivationContext,
    DesfireError,
    ErrorCode,
    KeyNumber,
    KeyPurpose,
    KeyRequest,
    Outcome,
)


@unittest.skipUnless(os.environ.get("DESFIRE_LIBRARY"), "Set DESFIRE_LIBRARY to the built C ABI")
class AsyncCardTests(unittest.IsolatedAsyncioTestCase):
    """Exercise one native worker per card without relying on timing-sensitive sleeps."""

    async def asyncSetUp(self) -> None:
        """Capture event-loop diagnostics so unobserved background failures fail the test."""
        self._asyncio_reports: list[str] = []
        loop = asyncio.get_running_loop()
        self._previous_exception_handler = loop.get_exception_handler()

        def record_exception(
            _loop: asyncio.AbstractEventLoop, context: dict[str, object]
        ) -> None:
            """Retain only the diagnostic category without copying private exception text."""
            self._asyncio_reports.append(str(context.get("message", "asyncio failure")))

        loop.set_exception_handler(record_exception)

    async def asyncTearDown(self) -> None:
        """Flush callbacks, restore the loop, and reject unobserved async failures."""
        await asyncio.sleep(0)
        asyncio.get_running_loop().set_exception_handler(self._previous_exception_handler)
        self.assertEqual(self._asyncio_reports, [])

    async def test_fifo_calls_run_on_one_non_event_loop_thread(self) -> None:
        """Concurrent callers retain FIFO wire order and never block the event-loop thread."""

        class Reader:
            """Return two deterministic FreeMemory results and record callback threads."""

            def __init__(self) -> None:
                """Start with no callback evidence."""
                self.threads: list[int] = []
                self.responses = [bytes.fromhex("0100009100"), bytes.fromhex("0200009100")]

            def exchange(self, request: bytes, timeout_ms: int) -> bytes:
                """Consume one response after checking the exact wrapped native command."""
                self.assert_request = request
                self.threads.append(threading.get_ident())
                return self.responses.pop(0)

        reader = Reader()
        event_thread = threading.get_ident()
        card = await AsyncCard.connect(os.environ["DESFIRE_LIBRARY"], reader)
        try:
            first = asyncio.create_task(card.free_memory())
            await asyncio.sleep(0)
            second = asyncio.create_task(card.free_memory())
            self.assertEqual(await asyncio.gather(first, second), [1, 2])
            self.assertEqual(reader.assert_request, bytes.fromhex("906e000000"))
            self.assertEqual(len(set(reader.threads)), 1)
            self.assertNotEqual(reader.threads[0], event_thread)
        finally:
            await card.close()

    async def test_queued_and_active_cancellation_preserve_delivery(self) -> None:
        """Queued work performs no I/O; active interruption retains the reader's unknown outcome."""

        class BlockingReader:
            """Hold the first exchange until its cancellation callback is invoked."""

            def __init__(self) -> None:
                """Create deterministic cross-thread synchronization."""
                self.started = threading.Event()
                self.cancelled = threading.Event()
                self.calls = 0
                self.cancel_thread = 0

            def exchange(self, request: bytes, timeout_ms: int) -> bytes:
                """Report an interrupted operation with unknown delivery."""
                self.calls += 1
                self.started.set()
                self.cancelled.wait(2)
                raise DesfireError(ErrorCode.CANCELLED, "interrupted", Outcome.UNKNOWN)

            def cancel(self) -> None:
                """Wake the active exchange without waiting for its worker."""
                self.cancel_thread = threading.get_ident()
                self.cancelled.set()

        reader = BlockingReader()
        card = await AsyncCard.connect(os.environ["DESFIRE_LIBRARY"], reader)
        active = asyncio.create_task(card.free_memory())
        await asyncio.to_thread(reader.started.wait, 2)
        queued = asyncio.create_task(card.file_ids())
        await asyncio.sleep(0)
        queued.cancel()
        with self.assertRaises(DesfireError) as queued_failure:
            await queued
        self.assertEqual(queued_failure.exception.outcome, Outcome.NOT_SENT)
        self.assertEqual(reader.calls, 1)
        active.cancel()
        with self.assertRaises(DesfireError) as active_failure:
            await active
        self.assertEqual(active_failure.exception.code, ErrorCode.CANCELLED)
        self.assertEqual(active_failure.exception.outcome, Outcome.UNKNOWN)
        self.assertNotEqual(reader.cancel_thread, threading.get_ident())
        await card.close()

    async def test_async_provider_failure_is_queued_redacted_and_unsent(self) -> None:
        """Async provider work runs on the main loop before native authentication I/O."""

        class NoIoReader:
            """Reject every exchange so a provider regression cannot pass silently."""

            calls = 0

            def exchange(self, request: bytes, timeout_ms: int) -> bytes:
                """Record and reject unexpected native I/O."""
                self.calls += 1
                raise AssertionError("provider failure must precede card I/O")

        class FailingProvider:
            """Capture its execution thread, yield once, and fail privately."""

            calls = 0
            thread = 0

            async def resolve(self, request: KeyRequest) -> Aes128Key:
                """Fail after a suspension point without leaking the provider diagnostic."""
                self.calls += 1
                self.thread = threading.get_ident()
                await asyncio.sleep(0)
                raise RuntimeError("private async provider")

        reader = NoIoReader()
        provider = FailingProvider()
        request = KeyRequest(
            b"async-key-ref",
            DerivationContext(KeyPurpose.AUTHENTICATION, KeyNumber(1)),
            AuthenticationProfile.STANDARD_AES,
        )
        card = await AsyncCard.connect(os.environ["DESFIRE_LIBRARY"], reader)
        try:
            with self.assertRaises(DesfireError) as failure:
                await card.authenticate_standard_aes(KeyNumber(1), AsyncProvider(request, provider))
            self.assertEqual(failure.exception.outcome, Outcome.NOT_SENT)
            self.assertNotIn("private", str(failure.exception))
            self.assertEqual(provider.thread, threading.get_ident())
            self.assertEqual(provider.calls, 1)
            self.assertEqual(reader.calls, 0)
        finally:
            await card.close()

    async def test_async_provider_cancellation_is_not_sent(self) -> None:
        """Cancelling an active async resolver cancels it and emits no authentication frame."""

        class NoIoReader:
            """Count unexpected card exchanges."""

            calls = 0

            def exchange(self, request: bytes, timeout_ms: int) -> bytes:
                """Reject any I/O performed after provider cancellation."""
                self.calls += 1
                raise AssertionError("cancelled provider must not reach the card")

        class WaitingProvider:
            """Wait until cancelled while reporting deterministic start evidence."""

            def __init__(self) -> None:
                """Create one event-loop-local start event."""
                self.started = asyncio.Event()

            async def resolve(self, request: KeyRequest) -> Aes128Key:
                """Suspend forever unless the SDK cancels this coroutine."""
                self.started.set()
                await asyncio.Event().wait()
                raise AssertionError("unreachable")

        reader = NoIoReader()
        provider = WaitingProvider()
        request = KeyRequest(
            b"cancel-key-ref",
            DerivationContext(KeyPurpose.AUTHENTICATION, KeyNumber(1)),
            AuthenticationProfile.STANDARD_AES,
        )
        card = await AsyncCard.connect(os.environ["DESFIRE_LIBRARY"], reader)
        operation = asyncio.create_task(
            card.authenticate_standard_aes(KeyNumber(1), AsyncProvider(request, provider))
        )
        await asyncio.wait_for(provider.started.wait(), 1)
        operation.cancel()
        with self.assertRaises(DesfireError) as failure:
            await operation
        self.assertEqual(failure.exception.code, ErrorCode.CANCELLED)
        self.assertEqual(failure.exception.outcome, Outcome.NOT_SENT)
        self.assertEqual(reader.calls, 0)
        await card.close()


if __name__ == "__main__":
    unittest.main()
