"""Async Card facade with one dedicated native-operation thread per card."""

from __future__ import annotations

import asyncio
import threading
from concurrent.futures import CancelledError as ConcurrentCancelledError
from concurrent.futures import Future as ConcurrentFuture
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from functools import partial
from typing import Any, Callable, TypeVar

from .card import Card
from .errors import DesfireError, ErrorCode, Outcome
from .keys import AsyncProvider, KeySource, Provider
from .models import AuthenticationInfo, KeyNumber
from .transport import Reader, TransportOptions

T = TypeVar("T")


async def _await_without_cancelling(future: asyncio.Future[T]) -> T:
    """Await one future without forwarding task cancellation to that future."""
    loop = asyncio.get_running_loop()
    waiter: asyncio.Future[T] = loop.create_future()

    def copy_completion(completed: asyncio.Future[T]) -> None:
        """Copy a completed result to the current waiter when it is still admitted."""
        if waiter.done():
            return
        if completed.cancelled():
            waiter.cancel()
            return
        failure = completed.exception()
        if failure is not None:
            waiter.set_exception(failure)
        else:
            waiter.set_result(completed.result())

    future.add_done_callback(copy_completion)
    try:
        return await waiter
    finally:
        future.remove_done_callback(copy_completion)


class _AsyncProviderBridge:
    """Run one async provider on its event loop while the card worker holds FIFO admission."""

    def __init__(self, source: AsyncProvider, loop: asyncio.AbstractEventLoop) -> None:
        """Retain provider metadata and cancellation state without copying key material."""
        self._source = source
        self._loop = loop
        self._lock = threading.Lock()
        self._future: ConcurrentFuture[Any] | None = None
        self._cancel_requested = False
        self._resolution_finished = False

    def resolve(self, request: Any) -> Any:
        """Block only the private card worker until main-loop resolution finishes."""
        future = asyncio.run_coroutine_threadsafe(
            self._source.provider.resolve(request), self._loop
        )
        with self._lock:
            self._future = future
            if self._cancel_requested:
                future.cancel()
        try:
            try:
                return future.result()
            except ConcurrentCancelledError:
                raise DesfireError(
                    ErrorCode.CANCELLED,
                    "Asynchronous key resolution was cancelled",
                    Outcome.NOT_SENT,
                ) from None
        finally:
            with self._lock:
                self._future = None
                self._resolution_finished = True

    def cancel(self) -> bool:
        """Cancel provider resolution and report whether native I/O is still impossible."""
        with self._lock:
            if self._resolution_finished:
                return False
            self._cancel_requested = True
            if self._future is not None:
                return self._future.cancel()
            return True


class AsyncCard:
    """Own a synchronous Card and serialize all native calls on one private thread."""

    def __init__(self, card: Card, executor: ThreadPoolExecutor) -> None:
        """Adopt a successfully opened Card and its single-worker executor."""
        self._card = card
        self._executor = executor
        self._closed = False
        self._closing = False

    @classmethod
    async def connect(
        cls,
        library: str,
        reader: Reader,
        options: TransportOptions = TransportOptions(),
    ) -> AsyncCard:
        """Open on a new private thread and clean up after failed construction."""
        executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="desfire-card")
        loop = asyncio.get_running_loop()
        try:
            card = await loop.run_in_executor(executor, partial(Card, library, reader, options))
            return cls(card, executor)
        except BaseException:
            executor.shutdown(wait=True, cancel_futures=True)
            raise

    async def __aenter__(self) -> AsyncCard:
        """Borrow this open card for an async context-manager scope."""
        if self._closed:
            raise RuntimeError("AsyncCard is closed")
        return self

    async def __aexit__(self, *_: object) -> None:
        """Close and join the private worker when leaving an async context."""
        await self.close()

    async def _run(
        self,
        function: Callable[..., T],
        *arguments: object,
        cancel_hook: Callable[[], bool] | None = None,
    ) -> T:
        """Submit one call; queued cancellation is unsent and active cancellation interrupts."""
        if self._closed or self._closing:
            raise RuntimeError("AsyncCard is closed")
        loop = asyncio.get_running_loop()
        work: ConcurrentFuture[T] = self._executor.submit(function, *arguments)
        wrapped = asyncio.wrap_future(work, loop=loop)
        try:
            return await _await_without_cancelling(wrapped)
        except asyncio.CancelledError:
            if work.cancel():
                raise DesfireError(
                    ErrorCode.CANCELLED,
                    "Queued card operation was cancelled",
                    Outcome.NOT_SENT,
                ) from None
            provider_cancelled = cancel_hook() if cancel_hook is not None else False
            cancellation: asyncio.Future[None] | None = None
            if not provider_cancelled:
                cancellation = loop.run_in_executor(None, self._card.cancel)
            try:
                result = await _await_without_cancelling(wrapped)
            except asyncio.CancelledError:
                raise DesfireError(
                    ErrorCode.CANCELLED,
                    "Active card operation was interrupted",
                    Outcome.UNKNOWN,
                ) from None
            finally:
                if cancellation is not None:
                    try:
                        await _await_without_cancelling(cancellation)
                    except BaseException:
                        # The operation result contains stronger delivery evidence. Cancellation
                        # callback failures remain observable through the explicit cancel method.
                        pass
            return result

    def __getattr__(self, name: str) -> Any:
        """Expose synchronous Card operations as awaitable private-worker methods."""
        operation = getattr(self._card, name)
        if not callable(operation):
            return operation

        async def invoke(*arguments: object, **keywords: object) -> Any:
            """Run one selected typed operation on the private worker."""
            call = partial(operation, *arguments, **keywords)
            return await self._run(call)

        return invoke

    def _provider_source(
        self,
        source: KeySource | AsyncProvider,
    ) -> tuple[KeySource, Callable[[], bool] | None]:
        """Bridge an async provider while leaving synchronous key sources unchanged."""
        if not isinstance(source, AsyncProvider):
            return source, None
        bridge = _AsyncProviderBridge(source, asyncio.get_running_loop())
        return Provider(source.request, bridge), bridge.cancel

    async def authenticate_standard_aes(
        self,
        key_number: KeyNumber,
        source: KeySource | AsyncProvider,
        timeout: timedelta = timedelta(seconds=5),
    ) -> None:
        """Resolve any synchronous or asynchronous source inside the card queue."""
        selected, cancel = self._provider_source(source)
        await self._run(
            self._card.authenticate_standard_aes,
            key_number,
            selected,
            timeout,
            cancel_hook=cancel,
        )

    async def authenticate_ev2_first_aes(
        self,
        key_number: KeyNumber,
        source: KeySource | AsyncProvider,
        timeout: timedelta = timedelta(seconds=5),
    ) -> AuthenticationInfo:
        """Establish EV2 First after queued sync or async key resolution."""
        selected, cancel = self._provider_source(source)
        return await self._run(
            self._card.authenticate_ev2_first_aes,
            key_number,
            selected,
            timeout,
            cancel_hook=cancel,
        )

    async def authenticate_ev2_first_aes_with_capabilities(
        self,
        key_number: KeyNumber,
        source: KeySource | AsyncProvider,
        pcd_capabilities: bytes = b"",
        timeout: timedelta = timedelta(seconds=5),
    ) -> AuthenticationInfo:
        """Establish EV2 First with explicit PCD capabilities and queued key resolution."""
        selected, cancel = self._provider_source(source)
        return await self._run(
            self._card.authenticate_ev2_first_aes_with_capabilities,
            key_number,
            selected,
            pcd_capabilities,
            timeout,
            cancel_hook=cancel,
        )

    async def authenticate_ev2_non_first_aes(
        self,
        key_number: KeyNumber,
        source: KeySource | AsyncProvider,
        timeout: timedelta = timedelta(seconds=5),
    ) -> AuthenticationInfo:
        """Replace EV2 session keys after queued sync or async key resolution."""
        selected, cancel = self._provider_source(source)
        return await self._run(
            self._card.authenticate_ev2_non_first_aes,
            key_number,
            selected,
            timeout,
            cancel_hook=cancel,
        )

    async def authenticate_iso_aes(
        self,
        key_number: KeyNumber,
        source: KeySource | AsyncProvider,
        application: bool = False,
        timeout: timedelta = timedelta(seconds=5),
    ) -> None:
        """Establish ISO AES after queued sync or async key resolution."""
        selected, cancel = self._provider_source(source)
        await self._run(
            self._card.authenticate_iso_aes,
            key_number,
            selected,
            application,
            timeout,
            cancel_hook=cancel,
        )

    async def cancel(self) -> None:
        """Request cancellation immediately; the active call retains outcome evidence."""
        self._card.cancel()

    async def close(self) -> None:
        """Drain admitted work, close once, and join the dedicated operation thread."""
        if self._closed:
            return
        if self._closing:
            while self._closing:
                await asyncio.sleep(0)
            if self._closed:
                return
        self._closing = True
        try:
            work = self._executor.submit(self._card.close)
            await _await_without_cancelling(asyncio.wrap_future(work))
        except BaseException:
            self._closing = False
            raise
        else:
            self._closed = True
            self._closing = False
            self._executor.shutdown(wait=True, cancel_futures=True)
