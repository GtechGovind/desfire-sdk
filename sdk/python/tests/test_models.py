"""Pure-Python contract tests that require no native library or card transport."""

import unittest

from desfire_ev3 import (
    Aes128Key,
    AuthenticationProfile,
    DerivationContext,
    Derived,
    DesfireError,
    Direct,
    ErrorCode,
    KeyNumber,
    KeyPurpose,
    KeyRequest,
    KeyScope,
    Outcome,
    Provider,
)
from desfire_ev3._operations import FUNCTIONS
from desfire_ev3.card import PROVIDER_C_SYMBOLS, SPECIAL_C_SYMBOLS
from desfire_ev3.keys import resolve_key_source
from desfire_ev3.offline import SUPPORTED_C_SYMBOLS as OFFLINE_C_SYMBOLS
from desfire_ev3.raw.card import SUPPORTED_C_SYMBOLS as RAW_C_SYMBOLS
from desfire_ev3.raw.operations_generated import OPERATIONS


class _Deriver:
    """Count calls and return an independently owned deterministic test key."""

    def __init__(self) -> None:
        """Start with no derivation calls."""
        self.calls = 0

    def derive(self, master_key: Aes128Key, context: DerivationContext) -> Aes128Key:
        """Return an exact key without retaining the provided objects."""
        self.calls += 1
        self.master_snapshot = master_key.snapshot()
        self.context = context
        return Aes128Key(bytes([0xA5]) * 16)


class _Provider:
    """Count provider calls and optionally inject a private failure."""

    def __init__(self, fail: bool = False) -> None:
        """Choose successful or failing deterministic behavior."""
        self.calls = 0
        self.fail = fail

    def resolve(self, request: KeyRequest) -> Aes128Key:
        """Return one scoped exact key or a diagnostic that must be redacted."""
        self.calls += 1
        self.request = request
        if self.fail:
            raise RuntimeError("private provider route")
        return Aes128Key(bytes([0x5A]) * 16)


class KeyContractTests(unittest.TestCase):
    """Verify strict key width, scope forwarding, wiping, and failure redaction."""

    def test_direct_snapshot_and_close(self) -> None:
        """Direct sources copy exactly sixteen bytes and closed owners cannot be reused."""
        key = Aes128Key(bytes(range(16)))
        temporary = resolve_key_source(
            Direct(key),
            KeyNumber(0),
            AuthenticationProfile.STANDARD_AES,
            KeyScope.NATIVE,
        )
        self.assertEqual(temporary, bytearray(range(16)))
        temporary[:] = bytes(16)
        key.close()
        with self.assertRaises(ValueError):
            key.snapshot()

    def test_derived_and_provider_are_called_exactly_once(self) -> None:
        """Custom callbacks receive the caller's full context once before native I/O."""
        context = DerivationContext(
            KeyPurpose.AUTHENTICATION,
            KeyNumber(3),
            diversification_input=b"uid",
            user_context=b"tenant",
        )
        deriver = _Deriver()
        derived = resolve_key_source(
            Derived(Aes128Key(bytes(16)), context, deriver),
            KeyNumber(3),
            AuthenticationProfile.EV2_FIRST,
            KeyScope.NATIVE,
        )
        self.assertEqual(deriver.calls, 1)
        self.assertEqual(derived, bytearray([0xA5] * 16))

        request = KeyRequest(b"key-ref", context, AuthenticationProfile.EV2_FIRST)
        provider = _Provider()
        resolved = resolve_key_source(
            Provider(request, provider),
            KeyNumber(3),
            AuthenticationProfile.EV2_FIRST,
            KeyScope.NATIVE,
        )
        self.assertEqual(provider.calls, 1)
        self.assertEqual(provider.request, request)
        self.assertEqual(resolved, bytearray([0x5A] * 16))

    def test_provider_failure_is_redacted_and_not_sent(self) -> None:
        """Provider exceptions expose no callback text and always report pre-I/O outcome."""
        context = DerivationContext(KeyPurpose.AUTHENTICATION, KeyNumber(1))
        provider = _Provider(fail=True)
        request = KeyRequest(b"key-ref", context, AuthenticationProfile.ISO_AES, KeyScope.ISO_PICC)
        with self.assertRaises(DesfireError) as failure:
            resolve_key_source(
                Provider(request, provider),
                KeyNumber(1),
                AuthenticationProfile.ISO_AES,
                KeyScope.ISO_PICC,
            )
        self.assertEqual(provider.calls, 1)
        self.assertEqual(failure.exception.code, ErrorCode.CRYPTO)
        self.assertEqual(failure.exception.outcome, Outcome.NOT_SENT)
        self.assertNotIn("private", str(failure.exception))

    def test_manifest_operation_surface_has_complete_python_coverage(self) -> None:
        """Every canonical operation maps to runtime, managed, raw, or offline Python behavior."""
        by_surface: dict[str, set[str]] = {}
        for _, symbol, surface in OPERATIONS.values():
            by_surface.setdefault(surface, set()).add(symbol)
        managed = set(FUNCTIONS) | set(PROVIDER_C_SYMBOLS) | set(SPECIAL_C_SYMBOLS)
        runtime = {"df_open", "df_close", "df_reset", "df_cancel", "df_notify_state_change"}
        self.assertEqual(by_surface["runtime"], runtime)
        self.assertEqual(by_surface["managed"], managed)
        self.assertEqual(by_surface["raw"], set(RAW_C_SYMBOLS))
        self.assertEqual(by_surface["offline"], set(OFFLINE_C_SYMBOLS))


if __name__ == "__main__":
    unittest.main()
