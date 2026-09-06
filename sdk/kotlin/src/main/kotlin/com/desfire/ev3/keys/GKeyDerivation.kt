package com.desfire.ev3.keys

import com.desfire.ev3.KeyProvider
import com.desfire.ev3.KeyRequest
import java.security.MessageDigest

/**
 * Optional AES-128 compatibility derivation for deployments that use GKey-formatted keys.
 *
 * This strategy has two independent stages. The `expand*` functions create a base key from
 * caller-owned UTF-8 seed bytes. [derive] binds an existing base key to the first six bytes of a
 * card UID. Callers that already manage base keys should use [derive] directly or [GKeyProvider].
 *
 * This object stores no seeds or keys. Returned arrays are caller-owned secrets and should be
 * cleared as soon as the operation completes.
 */
public object GKeyDerivation {
    /** Number of bytes in an AES-128 base or derived key. */
    public const val AES128_SIZE: Int = 16

    /** Number of UTF-8 bytes required for each compatibility seed. */
    public const val SEED_SIZE: Int = 32

    /** Minimum UID length; only the first six bytes participate in compatibility binding. */
    public const val UID_PREFIX_SIZE: Int = 6

    /**
     * Expand one 32-byte UTF-8 seed into an AES-128 base key.
     *
     * The function hashes the text bytes exactly as supplied. It does not decode hexadecimal text.
     */
    public fun expandSingleSeed(seedUtf8: ByteArray): ByteArray {
        requireSeed(seedUtf8)
        return expandDigest { digest -> digest.update(seedUtf8) }
    }

    /**
     * Expand the first and tenth 32-byte UTF-8 seeds into an application-master base key.
     *
     * Hash input is `firstSeed || tenthSeed` with no separator.
     */
    public fun expandApplicationMaster(
        firstSeedUtf8: ByteArray,
        tenthSeedUtf8: ByteArray,
    ): ByteArray {
        requireSeed(firstSeedUtf8)
        requireSeed(tenthSeedUtf8)
        return expandDigest { digest ->
            digest.update(firstSeedUtf8)
            digest.update(tenthSeedUtf8)
        }
    }

    /**
     * Expand ten ordered 32-byte UTF-8 seeds into a card-master base key.
     *
     * Hash input joins the seed bytes with the literal ASCII separator `, `.
     */
    public fun expandCardMaster(orderedSeedsUtf8: List<ByteArray>): ByteArray {
        require(orderedSeedsUtf8.size == CARD_MASTER_SEED_COUNT) {
            "GKey card-master expansion requires exactly ten seeds"
        }
        orderedSeedsUtf8.forEach(::requireSeed)
        return expandDigest { digest ->
            orderedSeedsUtf8.forEachIndexed { index, seed ->
                if (index != 0) digest.update(CARD_MASTER_SEPARATOR)
                digest.update(seed)
            }
        }
    }

    /**
     * Bind one AES-128 base key to a card UID using the GKey compatibility layout.
     *
     * The first twelve UID nibbles replace the high nibbles of key bytes 1 through 12. Key byte 0,
     * the affected low nibbles, and bytes 13 through 15 remain unchanged. UID bytes after the first
     * six are intentionally ignored for compatibility.
     */
    public fun derive(baseKey: ByteArray, cardUid: ByteArray): ByteArray {
        require(baseKey.size == AES128_SIZE) { "An AES-128 base key must contain sixteen bytes" }
        require(cardUid.size >= UID_PREFIX_SIZE) { "GKey derivation requires at least six UID bytes" }

        val result = baseKey.copyOf()
        repeat(UID_PREFIX_SIZE * 2) { nibbleIndex ->
            val uidByte = cardUid[nibbleIndex / 2].toInt() and 0xFF
            val uidNibble = if (nibbleIndex % 2 == 0) uidByte ushr 4 else uidByte and 0x0F
            val resultIndex = nibbleIndex + 1
            result[resultIndex] = ((uidNibble shl 4) or (result[resultIndex].toInt() and 0x0F)).toByte()
        }
        return result
    }

    /** Validate one seed without copying secret input. */
    private fun requireSeed(seedUtf8: ByteArray) {
        require(seedUtf8.size == SEED_SIZE) { "Each GKey seed must contain exactly 32 UTF-8 bytes" }
    }

    /** Hash caller-provided seed components and apply the compatibility byte transform. */
    private inline fun expandDigest(update: (MessageDigest) -> Unit): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        update(digest)
        val expanded = digest.digest()
        return try {
            for (index in expanded.indices) {
                val value = expanded[index].toInt() and 0xFF
                if (value < 0x10) expanded[index] = (0xA0 or value).toByte()
            }
            expanded.copyOf(AES128_SIZE)
        } finally {
            expanded.fill(0)
        }
    }

    private const val CARD_MASTER_SEED_COUNT = 10
    private val CARD_MASTER_SEPARATOR = byteArrayOf(','.code.toByte(), ' '.code.toByte())
}

/**
 * Thread-safe [KeyProvider] that applies [GKeyDerivation] to a provider-owned base-key copy.
 *
 * The provider reads the card UID from [KeyRequest.diversification]. One instance represents one
 * already-selected base key; request purpose, key number, application, key set, scope, and reference
 * do not select another key. [close] clears the retained base key and makes subsequent resolution
 * fail. The provider never logs secret material.
 */
public class GKeyProvider(baseKey: ByteArray) : KeyProvider, AutoCloseable {
    private val lock = Any()
    private val baseKeyBytes = baseKey.copyOf()
    private var closed = false

    init {
        if (baseKeyBytes.size != GKeyDerivation.AES128_SIZE) {
            baseKeyBytes.fill(0)
            throw IllegalArgumentException("An AES-128 base key must contain sixteen bytes")
        }
    }

    /** Resolve a fresh, disposable AES-128 key for the request's card UID. */
    override fun resolve(request: KeyRequest): ByteArray = synchronized(lock) {
        check(!closed) { "GKey provider is closed" }
        check(!request.cancellationRequested) { "GKey resolution was cancelled" }
        val cardUid = request.diversification
        try {
            GKeyDerivation.derive(baseKeyBytes, cardUid)
        } finally {
            cardUid.fill(0)
        }
    }

    /** Clear the retained base-key copy; repeated calls are safe. */
    override fun close(): Unit = synchronized(lock) {
        if (!closed) {
            baseKeyBytes.fill(0)
            closed = true
        }
    }

    /** Return a redacted description suitable for diagnostics. */
    override fun toString(): String = "GKeyProvider([REDACTED])"
}
