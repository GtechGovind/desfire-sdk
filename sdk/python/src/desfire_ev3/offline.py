"""Stateless host-side AES and originality helpers implemented by the native core."""

from __future__ import annotations

import ctypes as ct
import os
from typing import Any

from ._card import _check, _DelegatedApplicationConfiguration, _Error, _integer, _Library
from .errors import DesfireError, ErrorCode
from .keys import (
    Aes128Key,
    DerivationContext,
    KeyPurpose,
    KeyScope,
    KeySource,
    resolve_key_source,
)
from .models import ApplicationId, DelegatedApplicationConfiguration

SUPPORTED_C_SYMBOLS = frozenset(
    {
        "df_offline_derive_nxp_aes128",
        "df_offline_derive_nxp_aes128_provider",
        "df_offline_encrypt_delegated_default_key_aes",
        "df_offline_encrypt_delegated_default_key_aes_provider",
        "df_offline_calculate_delegated_application_mac_aes",
        "df_offline_calculate_delegated_application_mac_aes_provider",
        "df_offline_calculate_delegated_application_delete_mac_aes",
        "df_offline_calculate_delegated_application_delete_mac_aes_provider",
        "df_offline_calculate_delegated_configuration_mac_aes",
        "df_offline_calculate_delegated_configuration_mac_aes_provider",
        "df_offline_calculate_mfc_license_mac_aes",
        "df_offline_calculate_mfc_license_mac_aes_provider",
        "df_offline_derive_transaction_mac_keys_aes",
        "df_offline_derive_transaction_mac_keys_aes_provider",
        "df_offline_calculate_transaction_mac_session_aes",
        "df_offline_calculate_transaction_mac_aes",
        "df_offline_calculate_transaction_mac_aes_provider",
        "df_offline_verify_transaction_mac_aes",
        "df_offline_verify_transaction_mac_aes_provider",
        "df_offline_decrypt_transaction_reader_id_aes",
        "df_offline_verify_originality_uid_signature",
    }
)


def _input(value: bytes, name: str, maximum: int = 16 * 1024 * 1024) -> tuple[Any, int]:
    """Copy one bounded immutable input into call-owned C storage."""
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be immutable bytes")
    if len(value) > maximum:
        raise ValueError(f"{name} exceeds {maximum} bytes")
    return (ct.c_uint8 * len(value)).from_buffer_copy(value), len(value)


class Offline:
    """Manifest-checked stateless utilities from one explicitly selected native library."""

    def __init__(self, library: str | os.PathLike[str]) -> None:
        """Load and validate C ABI v1 and its canonical manifest hash."""
        self._library = _Library(library)

    def _buffer(self, result: ct.c_void_p) -> bytes:
        """Copy one native owned result and release it on every path."""
        if not result.value:
            raise DesfireError(ErrorCode.INTERNAL, "Native offline operation returned no buffer")
        try:
            size = self._library.native.df_buffer_size(result)
            data = self._library.native.df_buffer_data(result)
            if size > 16 * 1024 * 1024 or (size and not data):
                raise DesfireError(ErrorCode.INTERNAL, "Native offline output is invalid")
            return ct.string_at(data, size)
        finally:
            self._library.native.df_buffer_free(result)

    def _call_buffer(self, symbol: str, arguments: list[object]) -> bytes:
        """Call one native offline function and consume its owned byte output."""
        result = ct.c_void_p()
        error = _Error()
        status = getattr(self._library.native, symbol)(
            *arguments,
            ct.byref(result),
            ct.byref(error),
        )
        _check(status, error)
        return self._buffer(result)

    @staticmethod
    def _key_owner(key: Aes128Key) -> tuple[bytearray, Any]:
        """Create a wipeable Python snapshot and its call-owned C copy."""
        if not isinstance(key, Aes128Key):
            raise TypeError("key must be an Aes128Key")
        temporary = key.snapshot()
        return temporary, (ct.c_uint8 * 16).from_buffer_copy(temporary)

    @staticmethod
    def _configuration(
        value: DelegatedApplicationConfiguration,
    ) -> tuple[_DelegatedApplicationConfiguration, Any]:
        """Marshal one validated delegated configuration and retain its DF-name owner."""
        if not isinstance(value, DelegatedApplicationConfiguration):
            raise TypeError("configuration must be DelegatedApplicationConfiguration")
        name, size = _input(value.df_name, "df_name", 16)
        has_key_sets = value.active_key_set_version is not None
        descriptor = _DelegatedApplicationConfiguration(
            ct.sizeof(_DelegatedApplicationConfiguration),
            1,
            value.application.value,
            value.key_settings,
            value.number_of_keys,
            value.slot,
            value.slot_version,
            value.quota_limit,
            int(value.iso_file_identifiers),
            -1 if value.key_settings3 is None else value.key_settings3,
            -1 if value.iso_id is None else value.iso_id,
            name,
            size,
            int(has_key_sets),
            0 if value.active_key_set_version is None else value.active_key_set_version,
            value.number_of_key_sets,
            value.maximum_key_size,
            value.key_set_settings,
            (ct.c_uint64 * 8)(),
        )
        return descriptor, name

    @staticmethod
    def _resolved_key(
        source: KeySource,
        context: DerivationContext,
        purpose: KeyPurpose,
    ) -> tuple[Aes128Key, bytearray]:
        """Resolve one source for an offline operation and return two wipeable owners."""
        if not isinstance(context, DerivationContext):
            raise TypeError("context must be DerivationContext")
        temporary = resolve_key_source(
            source,
            context.key_number,
            None,
            KeyScope.NATIVE,
            purpose,
        )
        return Aes128Key(temporary), temporary

    def derive_nxp_aes128(self, master_key: Aes128Key, diversification: bytes) -> Aes128Key:
        """Derive an AES-128 key with the native NXP AN10922 implementation."""
        if not isinstance(master_key, Aes128Key):
            raise TypeError("master_key must be an Aes128Key")
        if not isinstance(diversification, bytes) or not 1 <= len(diversification) <= 31:
            raise ValueError("diversification must contain one through 31 bytes")
        temporary = master_key.snapshot()
        key = (ct.c_uint8 * 16).from_buffer_copy(temporary)
        context, size = _input(diversification, "diversification", 31)
        result = ct.c_void_p()
        try:
            error = _Error()
            status = self._library.native.df_offline_derive_nxp_aes128(
                key,
                16,
                context,
                size,
                ct.byref(result),
                ct.byref(error),
            )
            _check(status, error)
            derived = self._buffer(result)
            return Aes128Key(derived)
        finally:
            ct.memset(ct.addressof(key), 0, ct.sizeof(key))
            temporary[:] = bytes(len(temporary))

    def derive_nxp_aes128_from(
        self,
        source: KeySource,
        context: DerivationContext,
    ) -> Aes128Key:
        """Resolve a direct, derived, or provider master key and perform AN10922 derivation."""
        temporary = resolve_key_source(
            source,
            context.key_number,
            None,
            KeyScope.NATIVE,
            KeyPurpose.OFFLINE_OPERATION,
        )
        master = Aes128Key(temporary)
        try:
            return self.derive_nxp_aes128(master, context.diversification_input)
        finally:
            master.close()
            temporary[:] = bytes(len(temporary))

    def encrypt_delegated_default_key_aes(
        self,
        dam_encryption_key: Aes128Key,
        application_default_key: Aes128Key,
        application_default_key_version: int,
    ) -> bytes:
        """Encrypt a delegated application default key into the documented EncK record."""
        first, first_owner = self._key_owner(dam_encryption_key)
        second, second_owner = self._key_owner(application_default_key)
        try:
            return self._call_buffer(
                "df_offline_encrypt_delegated_default_key_aes",
                [
                    first_owner,
                    16,
                    second_owner,
                    16,
                    _integer(application_default_key_version, 0, 0xFF, "key version"),
                ],
            )
        finally:
            ct.memset(ct.addressof(first_owner), 0, ct.sizeof(first_owner))
            ct.memset(ct.addressof(second_owner), 0, ct.sizeof(second_owner))
            first[:] = bytes(16)
            second[:] = bytes(16)

    def encrypt_delegated_default_key_aes_from(
        self,
        dam_source: KeySource,
        context: DerivationContext,
        application_default_key: Aes128Key,
        application_default_key_version: int,
    ) -> bytes:
        """Resolve DAMEncKey before encrypting a supplied delegated default key."""
        key, temporary = self._resolved_key(
            dam_source,
            context,
            KeyPurpose.DELEGATED_APPLICATION,
        )
        try:
            return self.encrypt_delegated_default_key_aes(
                key,
                application_default_key,
                application_default_key_version,
            )
        finally:
            key.close()
            temporary[:] = bytes(16)

    def calculate_delegated_application_mac_aes(
        self,
        dam_mac_key: Aes128Key,
        configuration: DelegatedApplicationConfiguration,
        encrypted_default_key: bytes,
    ) -> bytes:
        """Calculate the eight-byte creation DAM MAC for exact application fields."""
        temporary, key = self._key_owner(dam_mac_key)
        descriptor, name = self._configuration(configuration)
        encrypted, encrypted_size = _input(encrypted_default_key, "encrypted_default_key", 32)
        try:
            return self._call_buffer(
                "df_offline_calculate_delegated_application_mac_aes",
                [key, 16, ct.byref(descriptor), encrypted, encrypted_size],
            )
        finally:
            del name
            ct.memset(ct.addressof(key), 0, ct.sizeof(key))
            temporary[:] = bytes(16)

    def calculate_delegated_application_mac_aes_from(
        self,
        source: KeySource,
        context: DerivationContext,
        configuration: DelegatedApplicationConfiguration,
        encrypted_default_key: bytes,
    ) -> bytes:
        """Resolve DAMMACKey before calculating a delegated creation MAC."""
        key, temporary = self._resolved_key(source, context, KeyPurpose.DELEGATED_APPLICATION)
        try:
            return self.calculate_delegated_application_mac_aes(
                key,
                configuration,
                encrypted_default_key,
            )
        finally:
            key.close()
            temporary[:] = bytes(16)

    def calculate_delegated_application_delete_mac_aes(
        self,
        dam_mac_key: Aes128Key,
        application: ApplicationId,
    ) -> bytes:
        """Calculate the issuer MAC authorizing one delegated application deletion."""
        if not isinstance(application, ApplicationId):
            raise TypeError("application must be an ApplicationId")
        temporary, key = self._key_owner(dam_mac_key)
        try:
            return self._call_buffer(
                "df_offline_calculate_delegated_application_delete_mac_aes",
                [key, 16, application.value],
            )
        finally:
            ct.memset(ct.addressof(key), 0, ct.sizeof(key))
            temporary[:] = bytes(16)

    def calculate_delegated_application_delete_mac_aes_from(
        self,
        source: KeySource,
        context: DerivationContext,
        application: ApplicationId,
    ) -> bytes:
        """Resolve DAMMACKey before calculating delegated deletion authorization."""
        key, temporary = self._resolved_key(source, context, KeyPurpose.DELEGATED_APPLICATION)
        try:
            return self.calculate_delegated_application_delete_mac_aes(key, application)
        finally:
            key.close()
            temporary[:] = bytes(16)

    def calculate_delegated_configuration_mac_aes(
        self,
        dam_mac_key: Aes128Key,
        old_df_name: bytes,
        new_df_name: bytes,
    ) -> bytes:
        """Calculate the eight-byte DAM MAC for one explicit DF-name replacement."""
        temporary, key = self._key_owner(dam_mac_key)
        old, old_size = _input(old_df_name, "old_df_name", 16)
        new, new_size = _input(new_df_name, "new_df_name", 16)
        try:
            return self._call_buffer(
                "df_offline_calculate_delegated_configuration_mac_aes",
                [key, 16, old, old_size, new, new_size],
            )
        finally:
            ct.memset(ct.addressof(key), 0, ct.sizeof(key))
            temporary[:] = bytes(16)

    def calculate_delegated_configuration_mac_aes_from(
        self,
        source: KeySource,
        context: DerivationContext,
        old_df_name: bytes,
        new_df_name: bytes,
    ) -> bytes:
        """Resolve DAMMACKey before calculating delegated DF-name authorization."""
        key, temporary = self._resolved_key(source, context, KeyPurpose.DELEGATED_APPLICATION)
        try:
            return self.calculate_delegated_configuration_mac_aes(
                key,
                old_df_name,
                new_df_name,
            )
        finally:
            key.close()
            temporary[:] = bytes(16)

    def calculate_mfc_license_mac_aes(
        self,
        license_mac_key: Aes128Key,
        license_record: bytes,
        sector_secrets: bytes,
    ) -> bytes:
        """Calculate the eight-byte AES MAC for a complete MIFARE Classic license record."""
        temporary, key = self._key_owner(license_mac_key)
        license_owner, license_size = _input(license_record, "license_record")
        secrets_owner, secrets_size = _input(sector_secrets, "sector_secrets")
        try:
            return self._call_buffer(
                "df_offline_calculate_mfc_license_mac_aes",
                [key, 16, license_owner, license_size, secrets_owner, secrets_size],
            )
        finally:
            ct.memset(ct.addressof(key), 0, ct.sizeof(key))
            temporary[:] = bytes(16)

    def calculate_mfc_license_mac_aes_from(
        self,
        source: KeySource,
        context: DerivationContext,
        license_record: bytes,
        sector_secrets: bytes,
    ) -> bytes:
        """Resolve an offline key before calculating the MIFARE Classic license MAC."""
        key, temporary = self._resolved_key(source, context, KeyPurpose.OFFLINE_OPERATION)
        try:
            return self.calculate_mfc_license_mac_aes(key, license_record, sector_secrets)
        finally:
            key.close()
            temporary[:] = bytes(16)

    def derive_transaction_mac_keys_aes(
        self,
        transaction_key: Aes128Key,
        transaction_counter: int,
        uid: bytes,
    ) -> bytes:
        """Derive SesTMMACKey followed by SesTMENCKey as one exact 32-byte result."""
        temporary, key = self._key_owner(transaction_key)
        uid_owner, uid_size = _input(uid, "uid", 16)
        try:
            return self._call_buffer(
                "df_offline_derive_transaction_mac_keys_aes",
                [
                    key,
                    16,
                    _integer(transaction_counter, 0, 0xFFFFFFFF, "transaction_counter"),
                    uid_owner,
                    uid_size,
                ],
            )
        finally:
            ct.memset(ct.addressof(key), 0, ct.sizeof(key))
            temporary[:] = bytes(16)

    def derive_transaction_mac_keys_aes_from(
        self,
        source: KeySource,
        context: DerivationContext,
        transaction_counter: int,
        uid: bytes,
    ) -> bytes:
        """Resolve AppTransactionMACKey before deriving transaction session keys."""
        key, temporary = self._resolved_key(source, context, KeyPurpose.TRANSACTION_MAC)
        try:
            return self.derive_transaction_mac_keys_aes(key, transaction_counter, uid)
        finally:
            key.close()
            temporary[:] = bytes(16)

    def calculate_transaction_mac_session_aes(
        self,
        session_mac_key: Aes128Key,
        transaction_input: bytes,
    ) -> bytes:
        """Calculate an eight-byte TMV from an already-derived session MAC key."""
        temporary, key = self._key_owner(session_mac_key)
        input_owner, input_size = _input(transaction_input, "transaction_input")
        try:
            return self._call_buffer(
                "df_offline_calculate_transaction_mac_session_aes",
                [key, 16, input_owner, input_size],
            )
        finally:
            ct.memset(ct.addressof(key), 0, ct.sizeof(key))
            temporary[:] = bytes(16)

    def calculate_transaction_mac_aes(
        self,
        transaction_mac_key: Aes128Key,
        transaction_counter: int,
        uid: bytes,
        transaction_input: bytes,
    ) -> bytes:
        """Calculate the documented eight-byte AES transaction MAC."""
        if not isinstance(transaction_mac_key, Aes128Key):
            raise TypeError("transaction_mac_key must be an Aes128Key")
        counter = _integer(transaction_counter, 0, 0xFFFFFFFF, "transaction_counter")
        uid_owner, uid_size = _input(uid, "uid", 16)
        input_owner, input_size = _input(transaction_input, "transaction_input")
        temporary = transaction_mac_key.snapshot()
        key = (ct.c_uint8 * 16).from_buffer_copy(temporary)
        result = ct.c_void_p()
        try:
            error = _Error()
            status = self._library.native.df_offline_calculate_transaction_mac_aes(
                key,
                16,
                counter,
                uid_owner,
                uid_size,
                input_owner,
                input_size,
                ct.byref(result),
                ct.byref(error),
            )
            _check(status, error)
            output = self._buffer(result)
            return output
        finally:
            ct.memset(ct.addressof(key), 0, ct.sizeof(key))
            temporary[:] = bytes(len(temporary))

    def calculate_transaction_mac_aes_from(
        self,
        source: KeySource,
        context: DerivationContext,
        transaction_counter: int,
        uid: bytes,
        transaction_input: bytes,
    ) -> bytes:
        """Resolve AppTransactionMACKey before calculating one transaction MAC."""
        key, temporary = self._resolved_key(source, context, KeyPurpose.TRANSACTION_MAC)
        try:
            return self.calculate_transaction_mac_aes(
                key,
                transaction_counter,
                uid,
                transaction_input,
            )
        finally:
            key.close()
            temporary[:] = bytes(16)

    def verify_transaction_mac_aes(
        self,
        transaction_key: Aes128Key,
        transaction_counter: int,
        uid: bytes,
        transaction_input: bytes,
        transaction_mac: bytes,
    ) -> bool:
        """Verify an eight-byte transaction MAC from its backend key and exact TMI."""
        temporary, key = self._key_owner(transaction_key)
        uid_owner, uid_size = _input(uid, "uid", 16)
        input_owner, input_size = _input(transaction_input, "transaction_input")
        mac_owner, mac_size = _input(transaction_mac, "transaction_mac", 8)
        verified = ct.c_uint32()
        try:
            error = _Error()
            status = self._library.native.df_offline_verify_transaction_mac_aes(
                key,
                16,
                _integer(transaction_counter, 0, 0xFFFFFFFF, "transaction_counter"),
                uid_owner,
                uid_size,
                input_owner,
                input_size,
                mac_owner,
                mac_size,
                ct.byref(verified),
                ct.byref(error),
            )
            _check(status, error)
            if verified.value not in (0, 1):
                raise DesfireError(ErrorCode.INTERNAL, "Native verification result is invalid")
            return bool(verified.value)
        finally:
            ct.memset(ct.addressof(key), 0, ct.sizeof(key))
            temporary[:] = bytes(16)

    def verify_transaction_mac_aes_from(
        self,
        source: KeySource,
        context: DerivationContext,
        transaction_counter: int,
        uid: bytes,
        transaction_input: bytes,
        transaction_mac: bytes,
    ) -> bool:
        """Resolve AppTransactionMACKey before verifying one transaction MAC."""
        key, temporary = self._resolved_key(source, context, KeyPurpose.TRANSACTION_MAC)
        try:
            return self.verify_transaction_mac_aes(
                key,
                transaction_counter,
                uid,
                transaction_input,
                transaction_mac,
            )
        finally:
            key.close()
            temporary[:] = bytes(16)

    def decrypt_transaction_reader_id_aes(
        self,
        session_encryption_key: Aes128Key,
        encrypted_reader_id: bytes,
    ) -> bytes:
        """Decrypt one exact EncTMRI with an already-derived session encryption key."""
        temporary, key = self._key_owner(session_encryption_key)
        encrypted, size = _input(encrypted_reader_id, "encrypted_reader_id", 16)
        try:
            return self._call_buffer(
                "df_offline_decrypt_transaction_reader_id_aes",
                [key, 16, encrypted, size],
            )
        finally:
            ct.memset(ct.addressof(key), 0, ct.sizeof(key))
            temporary[:] = bytes(16)

    def verify_originality_uid_signature(
        self,
        curve: str,
        public_key: bytes,
        uid: bytes,
        signature: bytes,
    ) -> bool:
        """Verify one UID originality signature with a caller-selected supported curve."""
        if not isinstance(curve, str) or not curve or "\x00" in curve:
            raise ValueError("curve must be a nonempty NUL-free string")
        curve_bytes = curve.encode("ascii")
        public_owner, public_size = _input(public_key, "public_key")
        uid_owner, uid_size = _input(uid, "uid", 16)
        signature_owner, signature_size = _input(signature, "signature")
        verified = ct.c_uint32()
        error = _Error()
        status = self._library.native.df_offline_verify_originality_uid_signature(
            curve_bytes,
            public_owner,
            public_size,
            uid_owner,
            uid_size,
            signature_owner,
            signature_size,
            ct.byref(verified),
            ct.byref(error),
        )
        _check(status, error)
        if verified.value not in (0, 1):
            raise DesfireError(ErrorCode.INTERNAL, "Native originality result is invalid")
        return bool(verified.value)


class NxpAes128Deriver:
    """Key-deriver adapter backed by the native AN10922 implementation."""

    def __init__(self, offline: Offline) -> None:
        """Retain one manifest-checked native utility facade."""
        if not isinstance(offline, Offline):
            raise TypeError("offline must be an Offline instance")
        self._offline = offline

    def derive(self, master_key: Aes128Key, context: DerivationContext) -> Aes128Key:
        """Derive from the caller's explicit diversification input."""
        if not isinstance(context, DerivationContext):
            raise TypeError("context must be DerivationContext")
        return self._offline.derive_nxp_aes128(master_key, context.diversification_input)


__all__ = ["NxpAes128Deriver", "Offline"]
