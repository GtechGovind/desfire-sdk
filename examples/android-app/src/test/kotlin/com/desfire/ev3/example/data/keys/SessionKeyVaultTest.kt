package com.desfire.ev3.example.data.keys

import com.desfire.ev3.example.domain.model.ExampleKeyMode
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** Verify deterministic key replacement and lifecycle generation guards without card hardware. */
class SessionKeyVaultTest {
    /** Clear a previously valid key before rejecting invalid replacement material. */
    @Test
    fun invalidReplacementLeavesVaultEmpty() {
        val vault = SessionKeyVault()
        vault.configure(ExampleKeyMode.DIRECT, ByteArray(16), byteArrayOf(), byteArrayOf())
        assertTrue(vault.configured())
        assertThrows(IllegalArgumentException::class.java) {
            vault.configure(ExampleKeyMode.DIRECT, ByteArray(15), byteArrayOf(), byteArrayOf())
        }
        assertFalse(vault.configured())
    }

    /** Prevent work admitted before clear from restoring a derived key afterward. */
    @Test
    fun staleDerivationCannotRepopulateAfterClear() {
        val vault = SessionKeyVault()
        vault.configure(ExampleKeyMode.DIRECT, ByteArray(16), byteArrayOf(), byteArrayOf())
        val lease = vault.offlineLease()
        vault.clear()
        try {
            assertFalse(vault.replaceWithDirectIfGeneration(lease.generation, ByteArray(16)))
            assertFalse(vault.configured())
        } finally {
            lease.close()
        }
    }

    /** Reject a queued authentication source after the user replaces its vault generation. */
    @Test
    fun staleAuthenticationCannotResolveReplacementKey() {
        val vault = SessionKeyVault()
        vault.configure(ExampleKeyMode.DIRECT, ByteArray(16), byteArrayOf(), byteArrayOf())
        val admittedGeneration = vault.generationToken()
        vault.configure(ExampleKeyMode.DIRECT, ByteArray(16) { 1 }, byteArrayOf(), byteArrayOf())
        assertThrows(IllegalStateException::class.java) {
            vault.source(expectedGeneration = admittedGeneration)
        }
    }

    /** Reject stale offline resolution for both callback and GKey provider modes. */
    @Test
    fun staleOfflineProviderCannotResolveReplacementKey() {
        listOf(ExampleKeyMode.PROVIDER, ExampleKeyMode.GKEY_PROVIDER).forEach { mode ->
            val vault = SessionKeyVault()
            val diversification = if (mode == ExampleKeyMode.GKEY_PROVIDER) ByteArray(6) else byteArrayOf()
            vault.configure(mode, ByteArray(16), diversification, byteArrayOf(1))
            val admittedGeneration = vault.offlineLease().use { it.generation }
            vault.configure(mode, ByteArray(16) { 1 }, diversification, byteArrayOf(2))
            assertThrows(IllegalStateException::class.java) {
                vault.source(
                    diversificationOverride = diversification,
                    expectedGeneration = admittedGeneration,
                )
            }
            vault.clear()
        }
    }
}
