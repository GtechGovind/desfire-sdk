package com.desfire.ev3.raw

import com.desfire.ev3.AuthenticationInfo
import com.desfire.ev3.AuthenticationProfile
import com.desfire.ev3.KeyNumber
import com.desfire.ev3.KeyScope
import com.desfire.ev3.KeySource

/** Establish a Standard AES session on this independent native raw channel. */
public fun BlockingRawChannel.authenticateStandardAes(
    keyNumber: KeyNumber,
    keySource: KeySource,
    timeoutMs: Long = 5_000,
) {
    authenticate(AuthenticationProfile.STANDARD_AES, KeyScope.NATIVE, keyNumber, false,
        keySource, byteArrayOf(), timeoutMs)
}

/** Establish EV2 First on this raw channel and return verified public metadata. */
public fun BlockingRawChannel.authenticateEv2FirstAes(
    keyNumber: KeyNumber,
    keySource: KeySource,
    pcdCapabilities: ByteArray = byteArrayOf(),
    timeoutMs: Long = 5_000,
): AuthenticationInfo {
    require(pcdCapabilities.size <= 6) { "PCD capabilities cannot exceed six bytes" }
    return AuthenticationInfo.decode(authenticate(AuthenticationProfile.EV2_FIRST,
        KeyScope.NATIVE, keyNumber, false, keySource, pcdCapabilities, timeoutMs))
}

/** Replace an active raw EV2 session through NonFirst. */
public fun BlockingRawChannel.authenticateEv2NonFirstAes(
    keyNumber: KeyNumber,
    keySource: KeySource,
    timeoutMs: Long = 5_000,
): AuthenticationInfo = AuthenticationInfo.decode(authenticate(AuthenticationProfile.EV2_NON_FIRST,
    KeyScope.NATIVE, keyNumber, false, keySource, byteArrayOf(), timeoutMs))

/** Establish ISO mutual AES on this independent ISO raw channel. */
public fun BlockingRawChannel.authenticateIsoAes(
    keyNumber: KeyNumber,
    application: Boolean,
    keySource: KeySource,
    timeoutMs: Long = 5_000,
) {
    authenticate(AuthenticationProfile.ISO_AES,
        if (application) KeyScope.ISO_APPLICATION else KeyScope.ISO_PICC,
        keyNumber, application, keySource, byteArrayOf(), timeoutMs)
}

/** Call one profile-specific raw JNI entrypoint under this channel's FIFO gate. */
private fun BlockingRawChannel.authenticate(
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
            is KeySource.Direct -> RawNative.authenticateDirect(handle, profile.code,
                keyNumber.value, application, keySource.keyBytes, pcdCapabilities, timeoutMs)
            is KeySource.Derived -> RawNative.authenticateDerived(handle, profile.code,
                keyNumber.value, application, keySource.masterKeyBytes,
                keySource.diversificationBytes, pcdCapabilities, timeoutMs)
            is KeySource.Provider -> RawNative.authenticateProvider(handle, profile.code, scope.code,
                keyNumber.value, application, keySource.bridge, keySource.referenceBytes,
                keySource.diversificationBytes, keySource.contextBytes,
                keySource.applicationId?.value ?: -1, keySource.keySet?.value ?: -1,
                pcdCapabilities, timeoutMs)
        }
    }
}

/** Suspend-friendly raw Standard AES authentication. */
public suspend fun RawChannel.authenticateStandardAes(
    keyNumber: KeyNumber,
    keySource: KeySource,
    timeoutMs: Long = 5_000,
): Unit = call { authenticateStandardAes(keyNumber, keySource, timeoutMs) }

/** Suspend-friendly raw EV2 First authentication. */
public suspend fun RawChannel.authenticateEv2FirstAes(
    keyNumber: KeyNumber,
    keySource: KeySource,
    pcdCapabilities: ByteArray = byteArrayOf(),
    timeoutMs: Long = 5_000,
): AuthenticationInfo = call {
    authenticateEv2FirstAes(keyNumber, keySource, pcdCapabilities, timeoutMs)
}

/** Suspend-friendly raw EV2 NonFirst authentication. */
public suspend fun RawChannel.authenticateEv2NonFirstAes(
    keyNumber: KeyNumber,
    keySource: KeySource,
    timeoutMs: Long = 5_000,
): AuthenticationInfo = call { authenticateEv2NonFirstAes(keyNumber, keySource, timeoutMs) }

/** Suspend-friendly raw ISO mutual AES authentication. */
public suspend fun RawChannel.authenticateIsoAes(
    keyNumber: KeyNumber,
    application: Boolean,
    keySource: KeySource,
    timeoutMs: Long = 5_000,
): Unit = call { authenticateIsoAes(keyNumber, application, keySource, timeoutMs) }
