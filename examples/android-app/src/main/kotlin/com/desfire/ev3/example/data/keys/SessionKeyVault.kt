package com.desfire.ev3.example.data.keys

import com.desfire.ev3.ApplicationId
import com.desfire.ev3.KeyProvider
import com.desfire.ev3.KeySource
import com.desfire.ev3.example.domain.model.ExampleKeyMode
import com.desfire.ev3.keys.GKeyProvider

/** Disposable secret snapshot used by one local operation. */
internal class SecretLease(
    val mode: ExampleKeyMode,
    val secret: ByteArray,
    val diversification: ByteArray,
    val generation: Long,
) : AutoCloseable {
    /** Overwrite every array owned by this lease. */
    override fun close() {
        secret.fill(0)
        diversification.fill(0)
    }
}

/**
 * Session-only key material for demonstration authentication and offline operations.
 *
 * The vault never persists, formats, compares, or logs secrets. Replaced arrays are overwritten.
 * A monotonic generation prevents a local derivation started before pause/clear from restoring a
 * key afterward. Kotlin and Android may retain compiler or heap copies outside this best-effort
 * boundary.
 */
internal class SessionKeyVault {
    private var mode: ExampleKeyMode? = null
    private var secret = byteArrayOf()
    private var diversification = byteArrayOf()
    private var reference = byteArrayOf()
    private var gKeyProvider: GKeyProvider? = null
    private var generation = 0L

    /** True when structurally valid user-provided key material is loaded. */
    @Synchronized
    fun configured(): Boolean = mode != null && secret.size == 16

    /** Replace the current key source, clearing an old valid key even when new input is invalid. */
    @Synchronized
    fun configure(
        selectedMode: ExampleKeyMode,
        secretBytes: ByteArray,
        diversificationBytes: ByteArray,
        referenceBytes: ByteArray,
    ) {
        wipeLocked()
        generation++
        require(secretBytes.size == 16) { "AES-128 key material must contain exactly 16 bytes." }
        if (selectedMode == ExampleKeyMode.DERIVED) {
            require(diversificationBytes.size in 1..31) {
                "Diversification input must contain 1 through 31 bytes."
            }
        }
        if (selectedMode == ExampleKeyMode.PROVIDER ||
            selectedMode == ExampleKeyMode.GKEY_PROVIDER
        ) {
            require(referenceBytes.isNotEmpty()) { "Provider reference cannot be empty." }
        }
        if (selectedMode == ExampleKeyMode.GKEY_PROVIDER) {
            require(diversificationBytes.size >= 6) {
                "GKey provider requires at least the first six UID bytes."
            }
        }
        mode = selectedMode
        secret = secretBytes.copyOf()
        diversification = diversificationBytes.copyOf()
        reference = referenceBytes.copyOf()
        if (selectedMode == ExampleKeyMode.GKEY_PROVIDER) {
            gKeyProvider = GKeyProvider(secret)
        }
    }

    /** Build a scoped SDK key source; direct and derived results must be closed after use. */
    @Synchronized
    fun source(
        applicationId: ApplicationId? = null,
        diversificationOverride: ByteArray? = null,
        expectedGeneration: Long? = null,
    ): KeySource {
        check(configured()) { "Load a session key source before authentication." }
        check(expectedGeneration == null || generation == expectedGeneration) {
            "The session key changed before the operation was admitted."
        }
        val sourceGeneration = generation
        val selectedDiversification = diversificationOverride ?: diversification
        return when (checkNotNull(mode)) {
            ExampleKeyMode.DIRECT -> KeySource.Direct(secret)
            ExampleKeyMode.DERIVED -> KeySource.Derived(secret, diversification)
            ExampleKeyMode.PROVIDER -> KeySource.Provider(
                provider = KeyProvider {
                    synchronized(this) { resolvedSecretCopy(sourceGeneration) }
                },
                reference = reference,
                diversification = selectedDiversification,
                applicationId = applicationId,
            )
            ExampleKeyMode.GKEY_PROVIDER -> KeySource.Provider(
                provider = checkNotNull(gKeyProvider),
                reference = reference,
                diversification = selectedDiversification,
                applicationId = applicationId,
            )
        }
    }

    /** Create a disposable snapshot for a local primitive and its generation guard. */
    @Synchronized
    fun offlineLease(): SecretLease {
        check(configured()) { "Load a session key source before an offline operation." }
        return SecretLease(
            mode = checkNotNull(mode),
            secret = secret.copyOf(),
            diversification = diversification.copyOf(),
            generation = generation,
        )
    }

    /** Capture the current generation for deferred authentication admission. */
    @Synchronized
    fun generationToken(): Long {
        check(configured()) { "Load a session key source before authentication." }
        return generation
    }

    /** Install a derived key only if no pause, clear, or replacement happened during derivation. */
    @Synchronized
    fun replaceWithDirectIfGeneration(expectedGeneration: Long, derived: ByteArray): Boolean {
        require(derived.size == 16) { "Derived AES-128 key must contain exactly 16 bytes." }
        if (generation != expectedGeneration || !configured()) return false
        wipeLocked()
        generation++
        mode = ExampleKeyMode.DIRECT
        secret = derived.copyOf()
        return true
    }

    /** Return only the selected family name. */
    @Synchronized
    fun description(): String = mode?.name ?: "NONE"

    /** Overwrite and release every array owned by this vault. */
    @Synchronized
    fun clear() {
        wipeLocked()
        generation++
    }

    /** Return one provider-owned copy after proving that the same provider remains configured. */
    private fun resolvedSecretCopy(expectedGeneration: Long): ByteArray {
        check(configured() && mode == ExampleKeyMode.PROVIDER && generation == expectedGeneration) {
            "Key provider is no longer active."
        }
        return secret.copyOf()
    }

    /** Clear current contents while the caller holds this object's monitor. */
    private fun wipeLocked() {
        gKeyProvider?.close()
        gKeyProvider = null
        secret.fill(0)
        diversification.fill(0)
        reference.fill(0)
        secret = byteArrayOf()
        diversification = byteArrayOf()
        reference = byteArrayOf()
        mode = null
    }
}
