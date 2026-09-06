package com.desfire.ev3

/** Authentication profile supplied to a key provider without secret card traffic. */
public enum class AuthenticationProfile(internal val code: Int) {
    STANDARD_AES(0),
    EV2_FIRST(1),
    EV2_NON_FIRST(2),
    ISO_AES(3),
}

/** Reason an AES key is being resolved at one native boundary. */
public enum class KeyPurpose(internal val code: Int) {
    AUTHENTICATION(0),
    CURRENT_KEY(1),
    REPLACEMENT_KEY(2),
    DELEGATED_APPLICATION(3),
    TRANSACTION_MAC(4),
    OFFLINE_OPERATION(5),
}

/** Scope of the key selector supplied to a key provider. */
public enum class KeyScope(internal val code: Int) {
    NATIVE(0),
    ISO_PICC(1),
    ISO_APPLICATION(2),
}

/** Optional EV3 key-set selector carried as non-secret provider metadata. */
@JvmInline
public value class KeySetNumber(public val value: Int) {
    init {
        require(value in 0..15) { "Key-set number must be between zero and fifteen" }
    }
}

/**
 * Non-secret description of one exact AES-128 key resolution.
 *
 * Array properties return copies. A provider must return exactly sixteen exportable AES bytes and
 * must not place key material in an exception message.
 */
public class KeyRequest internal constructor(
    public val purpose: KeyPurpose,
    public val profile: AuthenticationProfile?,
    public val scope: KeyScope,
    public val keyNumber: KeyNumber,
    public val applicationId: ApplicationId?,
    public val keySet: KeySetNumber?,
    reference: ByteArray,
    diversification: ByteArray,
    userContext: ByteArray,
    public val cancellationRequested: Boolean,
) {
    private val referenceBytes = reference.copyOf()
    private val diversificationBytes = diversification.copyOf()
    private val contextBytes = userContext.copyOf()

    /** Provider-specific non-secret identifier. */
    public val reference: ByteArray
        get() = referenceBytes.copyOf()

    /** Construction-specific diversification input. */
    public val diversification: ByteArray
        get() = diversificationBytes.copyOf()

    /** Non-secret provider routing context. */
    public val userContext: ByteArray
        get() = contextBytes.copyOf()
}

/** Synchronous key resolver used at the native authentication boundary before card I/O. */
public fun interface KeyProvider {
    /** Resolve exactly one exportable AES-128 key or throw a secret-free failure. */
    public fun resolve(request: KeyRequest): ByteArray
}

/**
 * Source of exactly one AES-128 authentication key.
 *
 * Constructors copy every array. Instances intentionally do not expose key bytes, implement data
 * class semantics, or include secrets in [toString].
 */
public sealed class KeySource private constructor() {
    /** One already resolved AES-128 key. */
    public class Direct(key: ByteArray) : KeySource() {
        internal val keyBytes = key.copyOf()

        init {
            require(keyBytes.size == AES128_SIZE) { "An AES-128 key must contain sixteen bytes" }
        }

        override fun toString(): String = "KeySource.Direct([REDACTED])"
    }

    /** NXP AES-128 CMAC diversification from a master key and one through 31 input bytes. */
    public class Derived(masterKey: ByteArray, diversification: ByteArray) : KeySource() {
        internal val masterKeyBytes = masterKey.copyOf()
        internal val diversificationBytes = diversification.copyOf()

        init {
            require(masterKeyBytes.size == AES128_SIZE) {
                "An AES-128 master key must contain sixteen bytes"
            }
            require(diversificationBytes.size in 1..31) {
                "NXP diversification input must contain one through 31 bytes"
            }
        }

        override fun toString(): String = "KeySource.Derived([REDACTED])"
    }

    /**
     * Caller-owned resolver plus non-secret routing metadata.
     *
     * The provider is invoked exactly once for an admitted authentication call. Resolution occurs
     * before the first card frame and its failure therefore has NOT_SENT delivery evidence.
     */
    public class Provider(
        public val provider: KeyProvider,
        reference: ByteArray,
        diversification: ByteArray = byteArrayOf(),
        userContext: ByteArray = byteArrayOf(),
        public val applicationId: ApplicationId? = null,
        public val keySet: KeySetNumber? = null,
    ) : KeySource() {
        internal val referenceBytes = reference.copyOf()
        internal val diversificationBytes = diversification.copyOf()
        internal val contextBytes = userContext.copyOf()
        internal val bridge = ProviderBridge(this)

        init {
            require(referenceBytes.size in 1..1024) {
                "Provider reference must contain one through 1024 bytes"
            }
            require(diversificationBytes.size + contextBytes.size <= 65_536) {
                "Diversification and provider context exceed 65536 bytes"
            }
        }

        override fun toString(): String = "KeySource.Provider(referenceSize=${referenceBytes.size})"
    }

    private companion object {
        private const val AES128_SIZE = 16
    }
}

/** Stable Java-callable adapter kept internal so JNI never reflects over public implementations. */
internal class ProviderBridge(private val source: KeySource.Provider) {
    /** Build the public request, invoke the provider once, and return a disposable key copy. */
    @Suppress("LongParameterList")
    fun resolve(
        purpose: Int,
        profile: Int,
        scope: Int,
        keyNumber: Int,
        applicationId: Int,
        keySet: Int,
        reference: ByteArray,
        diversification: ByteArray,
        userContext: ByteArray,
        cancelled: Boolean,
    ): ByteArray {
        val request = KeyRequest(
            KeyPurpose.entries.first { it.code == purpose },
            profile.takeUnless { it == -1 }?.let { code ->
                AuthenticationProfile.entries.first { it.code == code }
            },
            KeyScope.entries.first { it.code == scope },
            KeyNumber(keyNumber),
            applicationId.takeUnless { it == -1 }?.let(::ApplicationId),
            keySet.takeUnless { it == -1 }?.let(::KeySetNumber),
            reference,
            diversification,
            userContext,
            cancelled,
        )
        val resolved = source.provider.resolve(request)
        require(resolved.size == 16) { "Key provider must return exactly sixteen bytes" }
        return resolved.copyOf()
    }
}

/** Public, verified metadata returned by EV2 authentication. */
public class AuthenticationInfo internal constructor(
    transactionIdentifier: ByteArray,
    piccCapabilities: ByteArray,
    pcdCapabilities: ByteArray,
) {
    private val transactionIdentifierBytes = transactionIdentifier.copyOf()
    private val piccCapabilityBytes = piccCapabilities.copyOf()
    private val pcdCapabilityBytes = pcdCapabilities.copyOf()

    /** Four-byte EV2 transaction identifier. */
    public val transactionIdentifier: ByteArray
        get() = transactionIdentifierBytes.copyOf()

    /** Six verified PICC capability bytes. */
    public val piccCapabilities: ByteArray
        get() = piccCapabilityBytes.copyOf()

    /** Six verified padded PCD capability bytes. */
    public val pcdCapabilities: ByteArray
        get() = pcdCapabilityBytes.copyOf()

    override fun toString(): String = "AuthenticationInfo(transactionIdentifier=[REDACTED])"

    internal companion object {
        /** Decode the fixed 4 + 6 + 6 byte C ABI authentication result. */
        fun decode(bytes: ByteArray): AuthenticationInfo {
            check(bytes.size == 16) { "Malformed EV2 authentication metadata" }
            return AuthenticationInfo(
                bytes.copyOfRange(0, 4),
                bytes.copyOfRange(4, 10),
                bytes.copyOfRange(10, 16),
            )
        }
    }
}
