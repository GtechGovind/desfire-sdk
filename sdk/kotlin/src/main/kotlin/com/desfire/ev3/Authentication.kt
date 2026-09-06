package com.desfire.ev3

/** Establish Standard AES with the selected native key. */
public fun BlockingCard.authenticateStandardAes(
    keyNumber: KeyNumber,
    keySource: KeySource,
    timeoutMs: Long = 5_000,
) {
    requireEmptyNativeResult(
        authenticate(AuthenticationProfile.STANDARD_AES, KeyScope.NATIVE, keyNumber, false,
            keySource, byteArrayOf(), timeoutMs),
        "Unexpected Standard AES authentication result payload",
    )
}

/** Establish EV2 First and return verified transaction and capability metadata. */
public fun BlockingCard.authenticateEv2FirstAes(
    keyNumber: KeyNumber,
    keySource: KeySource,
    pcdCapabilities: ByteArray = byteArrayOf(),
    timeoutMs: Long = 5_000,
): AuthenticationInfo {
    require(pcdCapabilities.size <= 6) { "PCD capabilities cannot exceed six bytes" }
    return AuthenticationInfo.decode(
        authenticate(AuthenticationProfile.EV2_FIRST, KeyScope.NATIVE, keyNumber, false,
            keySource, pcdCapabilities, timeoutMs),
    )
}

/** Replace an active EV2 session through NonFirst while preserving its transaction context. */
public fun BlockingCard.authenticateEv2NonFirstAes(
    keyNumber: KeyNumber,
    keySource: KeySource,
    timeoutMs: Long = 5_000,
): AuthenticationInfo = AuthenticationInfo.decode(
    authenticate(AuthenticationProfile.EV2_NON_FIRST, KeyScope.NATIVE, keyNumber, false,
        keySource, byteArrayOf(), timeoutMs),
)

/** Establish ISO mutual AES in PICC or application scope. */
public fun BlockingCard.authenticateIsoAes(
    keyNumber: KeyNumber,
    application: Boolean,
    keySource: KeySource,
    timeoutMs: Long = 5_000,
) {
    val scope = if (application) KeyScope.ISO_APPLICATION else KeyScope.ISO_PICC
    requireEmptyNativeResult(
        authenticate(AuthenticationProfile.ISO_AES, scope, keyNumber, application,
            keySource, byteArrayOf(), timeoutMs),
        "Unexpected ISO AES authentication result payload",
    )
}

/** Invoke one profile-specific JNI entrypoint without exposing key bytes to generic dispatch. */
private fun BlockingCard.authenticate(
    profile: AuthenticationProfile,
    scope: KeyScope,
    keyNumber: KeyNumber,
    application: Boolean,
    keySource: KeySource,
    pcdCapabilities: ByteArray,
    timeoutMs: Long,
): ByteArray {
    require(timeoutMs in 1..0xFFFF_FFFFL) { "Timeout must fit a positive unsigned 32-bit value" }
    return withExclusiveHandle { handle ->
        when (keySource) {
            is KeySource.Direct -> Native.authenticateDirect(
                handle, profile.code, keyNumber.value, application, keySource.keyBytes,
                pcdCapabilities, timeoutMs,
            )
            is KeySource.Derived -> Native.authenticateDerived(
                handle, profile.code, keyNumber.value, application, keySource.masterKeyBytes,
                keySource.diversificationBytes, pcdCapabilities, timeoutMs,
            )
            is KeySource.Provider -> Native.authenticateProvider(
                handle, profile.code, scope.code, keyNumber.value, application,
                keySource.bridge, keySource.referenceBytes, keySource.diversificationBytes,
                keySource.contextBytes, keySource.applicationId?.value ?: -1,
                keySource.keySet?.value ?: -1, pcdCapabilities, timeoutMs,
            )
        }
    }
}

/** Suspend-friendly Standard AES authentication. */
public suspend fun Card.authenticateStandardAes(
    keyNumber: KeyNumber,
    keySource: KeySource,
    timeoutMs: Long = 5_000,
): Unit = call { authenticateStandardAes(keyNumber, keySource, timeoutMs) }

/** Suspend-friendly EV2 First authentication. */
public suspend fun Card.authenticateEv2FirstAes(
    keyNumber: KeyNumber,
    keySource: KeySource,
    pcdCapabilities: ByteArray = byteArrayOf(),
    timeoutMs: Long = 5_000,
): AuthenticationInfo = call {
    authenticateEv2FirstAes(keyNumber, keySource, pcdCapabilities, timeoutMs)
}

/** Suspend-friendly EV2 NonFirst authentication. */
public suspend fun Card.authenticateEv2NonFirstAes(
    keyNumber: KeyNumber,
    keySource: KeySource,
    timeoutMs: Long = 5_000,
): AuthenticationInfo = call { authenticateEv2NonFirstAes(keyNumber, keySource, timeoutMs) }

/** Suspend-friendly ISO mutual AES authentication. */
public suspend fun Card.authenticateIsoAes(
    keyNumber: KeyNumber,
    application: Boolean,
    keySource: KeySource,
    timeoutMs: Long = 5_000,
): Unit = call { authenticateIsoAes(keyNumber, application, keySource, timeoutMs) }
