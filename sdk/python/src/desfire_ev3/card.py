"""Synchronous friendly Card API backed by the stable C ABI."""

from __future__ import annotations

from datetime import timedelta
from typing import Any, cast

from ._card import Card as _AbiCard
from .errors import DesfireError, ErrorCode, Outcome
from .keys import (
    AuthenticationProfile,
    KeyPurpose,
    KeyScope,
    KeySource,
    resolve_key_source,
)
from .models import (
    ApplicationId,
    AuthenticationInfo,
    FileNumber,
    KeyNumber,
    PiccConfiguration,
    TransactionOperation,
    TransactionReceipt,
)

PROVIDER_C_SYMBOLS = frozenset(
    {
        "df_authenticate_standard_aes_provider",
        "df_authenticate_ev2_first_aes_provider",
        "df_authenticate_ev2_first_aes_with_capabilities_provider",
        "df_authenticate_ev2_non_first_aes_provider",
        "df_authenticate_iso_aes_provider",
        "df_set_default_aes_key_provider",
        "df_change_aes_key_provider",
        "df_create_transaction_mac_file_provider",
    }
)
SPECIAL_C_SYMBOLS = frozenset({"df_set_picc_configuration", "df_execute_transaction"})


def _timeout_ms(timeout: timedelta) -> int:
    """Convert one positive duration to a bounded whole-millisecond operation budget."""
    if not isinstance(timeout, timedelta):
        raise TypeError("timeout must be datetime.timedelta")
    milliseconds = timeout.total_seconds() * 1000
    if milliseconds < 1 or milliseconds > 0xFFFFFFFF or not milliseconds.is_integer():
        raise ValueError("timeout must be a whole number of milliseconds in the ABI range")
    return int(milliseconds)


class Card(_AbiCard):
    """Friendly synchronous Card with typed authentication and FIFO key resolution."""

    def _authenticate_with_key(
        self,
        symbol: str,
        key_number: KeyNumber,
        source: KeySource,
        profile: AuthenticationProfile,
        scope: KeyScope,
        arguments: tuple[Any, ...],
        prefix_before_key: bool = False,
    ) -> Any:
        """Resolve and consume one key inside the same admission as the first card frame."""
        if symbol not in self._known_operations():
            raise DesfireError(
                ErrorCode.INTERNAL,
                "Python binding manifest lacks authentication operation",
                Outcome.NOT_SENT,
            )
        handle = self._enter_operation()
        temporary = bytearray()
        try:
            temporary = resolve_key_source(source, key_number, profile, scope)
            if prefix_before_key:
                return self._invoke_admitted(
                    handle,
                    symbol,
                    (key_number.value, *arguments[:-1], temporary, arguments[-1]),
                )
            return self._invoke_admitted(handle, symbol, (key_number.value, temporary, *arguments))
        finally:
            temporary[:] = bytes(len(temporary))
            self._leave_operation()

    @staticmethod
    def _known_operations() -> frozenset[str]:
        """Return C symbols compiled into the generated ctypes dispatch table."""
        from ._operations import FUNCTIONS

        return frozenset(FUNCTIONS)

    def authenticate_standard_aes(
        self,
        key_number: KeyNumber,
        source: KeySource,
        timeout: timedelta = timedelta(seconds=5),
    ) -> None:
        """Establish native Standard AES using one direct, derived, or provider key."""
        self._authenticate_with_key(
            "df_authenticate_standard_aes",
            key_number,
            source,
            AuthenticationProfile.STANDARD_AES,
            KeyScope.NATIVE,
            (_timeout_ms(timeout),),
        )

    def authenticate_ev2_first_aes(
        self,
        key_number: KeyNumber,
        source: KeySource,
        timeout: timedelta = timedelta(seconds=5),
    ) -> AuthenticationInfo:
        """Establish EV2 First with no PCD capabilities and return verified metadata."""
        return cast(
            AuthenticationInfo,
            self._authenticate_with_key(
                "df_authenticate_ev2_first_aes",
                key_number,
                source,
                AuthenticationProfile.EV2_FIRST,
                KeyScope.NATIVE,
                (_timeout_ms(timeout),),
            ),
        )

    def authenticate_ev2_first_aes_with_capabilities(
        self,
        key_number: KeyNumber,
        source: KeySource,
        pcd_capabilities: bytes = b"",
        timeout: timedelta = timedelta(seconds=5),
    ) -> AuthenticationInfo:
        """Establish EV2 First with zero through six explicit PCD capability bytes."""
        if not isinstance(pcd_capabilities, bytes) or len(pcd_capabilities) > 6:
            raise ValueError("pcd_capabilities must contain zero through six bytes")
        return cast(
            AuthenticationInfo,
            self._authenticate_with_key(
                "df_authenticate_ev2_first_aes_with_capabilities",
                key_number,
                source,
                AuthenticationProfile.EV2_FIRST,
                KeyScope.NATIVE,
                (pcd_capabilities, _timeout_ms(timeout)),
            ),
        )

    def authenticate_ev2_non_first_aes(
        self,
        key_number: KeyNumber,
        source: KeySource,
        timeout: timedelta = timedelta(seconds=5),
    ) -> AuthenticationInfo:
        """Replace an active EV2 session while preserving its transaction identity and counter."""
        return cast(
            AuthenticationInfo,
            self._authenticate_with_key(
                "df_authenticate_ev2_non_first_aes",
                key_number,
                source,
                AuthenticationProfile.EV2_NON_FIRST,
                KeyScope.NATIVE,
                (_timeout_ms(timeout),),
            ),
        )

    def authenticate_iso_aes(
        self,
        key_number: KeyNumber,
        source: KeySource,
        application: bool = False,
        timeout: timedelta = timedelta(seconds=5),
    ) -> None:
        """Establish ISO mutual AES in PICC-master or application-key scope."""
        if not isinstance(application, bool):
            raise TypeError("application must be a bool")
        scope = KeyScope.ISO_APPLICATION if application else KeyScope.ISO_PICC
        self._authenticate_with_key(
            "df_authenticate_iso_aes",
            key_number,
            source,
            AuthenticationProfile.ISO_AES,
            scope,
            (int(application), _timeout_ms(timeout)),
            True,
        )

    def select(self, application: ApplicationId, timeout: timedelta = timedelta(seconds=5)) -> None:
        """Select an application with a strong 24-bit identifier and clear session state."""
        if not isinstance(application, ApplicationId):
            raise TypeError("application must be an ApplicationId")
        self._invoke("df_select_application", (application.value, _timeout_ms(timeout)))

    def set_picc_configuration(
        self,
        configuration: PiccConfiguration,
        timeout: timedelta = timedelta(seconds=5),
    ) -> None:
        """Apply documented PICC flags using a named versioned descriptor."""
        if not isinstance(configuration, PiccConfiguration):
            raise TypeError("configuration must be PiccConfiguration")
        self._set_picc_configuration(configuration, _timeout_ms(timeout))

    def execute_transaction(
        self,
        operations: tuple[TransactionOperation, ...],
        return_mac: bool = False,
        timeout: timedelta = timedelta(seconds=5),
    ) -> TransactionReceipt:
        """Execute checked mutations and their commit as one serialized card operation."""
        if not isinstance(operations, tuple) or not all(
            isinstance(operation, TransactionOperation) for operation in operations
        ):
            raise TypeError("operations must be a tuple of TransactionOperation values")
        return TransactionReceipt(
            self._execute_transaction(operations, return_mac, _timeout_ms(timeout)),
        )

    def set_default_aes_key_from(
        self,
        source: KeySource,
        key_version: int,
        timeout: timedelta = timedelta(seconds=5),
    ) -> None:
        """Resolve one replacement key under FIFO admission and set the default AES key."""
        handle = self._enter_operation()
        temporary = bytearray()
        try:
            temporary = resolve_key_source(
                source,
                KeyNumber(0),
                None,
                KeyScope.NATIVE,
                KeyPurpose.REPLACEMENT_KEY,
            )
            self._invoke_admitted(
                handle,
                "df_set_default_aes_key",
                (temporary, key_version, _timeout_ms(timeout)),
            )
        finally:
            temporary[:] = bytes(len(temporary))
            self._leave_operation()

    def create_transaction_mac_file_from(
        self,
        file: FileNumber,
        access_rights: int,
        source: KeySource,
        version: int,
        timeout: timedelta = timedelta(seconds=5),
    ) -> None:
        """Resolve a transaction-MAC key and create its file without exposing key bytes."""
        if not isinstance(file, FileNumber):
            raise TypeError("file must be a FileNumber")
        handle = self._enter_operation()
        temporary = bytearray()
        try:
            temporary = resolve_key_source(
                source,
                KeyNumber(file.value),
                None,
                KeyScope.NATIVE,
                KeyPurpose.TRANSACTION_MAC,
            )
            self._invoke_admitted(
                handle,
                "df_create_transaction_mac_file",
                (file.value, access_rights, temporary, version, _timeout_ms(timeout)),
            )
        finally:
            temporary[:] = bytes(len(temporary))
            self._leave_operation()

    def change_aes_key_from(
        self,
        key_number: KeyNumber,
        new_source: KeySource,
        version: int,
        authenticated_key: bool,
        old_source: KeySource | None = None,
        key_set: int = -1,
        picc_master: bool = False,
        timeout: timedelta = timedelta(seconds=5),
    ) -> None:
        """Resolve replacement and optional current keys once before issuing ChangeKey."""
        if not isinstance(key_number, KeyNumber):
            raise TypeError("key_number must be a KeyNumber")
        if not isinstance(authenticated_key, bool) or not isinstance(picc_master, bool):
            raise TypeError("authenticated_key and picc_master must be bool values")
        handle = self._enter_operation()
        new_key = bytearray()
        old_key = bytearray()
        try:
            new_key = resolve_key_source(
                new_source,
                key_number,
                None,
                KeyScope.NATIVE,
                KeyPurpose.REPLACEMENT_KEY,
            )
            if old_source is not None:
                old_key = resolve_key_source(
                    old_source,
                    key_number,
                    None,
                    KeyScope.NATIVE,
                    KeyPurpose.CURRENT_KEY,
                )
            self._invoke_admitted(
                handle,
                "df_change_aes_key",
                (
                    key_number.value,
                    new_key,
                    version,
                    int(authenticated_key),
                    old_key,
                    key_set,
                    int(picc_master),
                    _timeout_ms(timeout),
                ),
            )
        finally:
            new_key[:] = bytes(len(new_key))
            old_key[:] = bytes(len(old_key))
            self._leave_operation()


__all__ = ["Card"]
