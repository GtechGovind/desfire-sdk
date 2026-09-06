package com.desfire.ev3.offline

import com.desfire.ev3.MalformedNativeResultException
import com.desfire.ev3.KeyScope
import com.desfire.ev3.KeySource
import com.desfire.ev3.KeyNumber
import com.desfire.ev3.DelegatedApplication

/** Derive one AES-128 key using the documented NXP AN10922 construction. */
public fun deriveNxpAes128(masterKey: ByteArray, diversification: ByteArray): ByteArray {
    require(masterKey.size == 16) { "An AES-128 master key must contain sixteen bytes" }
    require(diversification.size in 1..31) {
        "Diversification input must contain one through 31 bytes"
    }
    return exactOfflineResult(
        OfflineNative.deriveDirect(masterKey, diversification), 16,
        "Malformed native AES-128 derivation result",
    )
}

/** Resolve one provider master key and derive it using the provider diversification bytes. */
public fun deriveNxpAes128(
    masterKey: KeySource.Provider,
    keyNumber: KeyNumber = KeyNumber(0),
): ByteArray {
    require(masterKey.diversificationBytes.size in 1..31) {
        "Provider diversification input must contain one through 31 bytes"
    }
    return exactOfflineResult(OfflineNative.deriveProvider(
        masterKey.bridge, KeyScope.NATIVE.code, keyNumber.value, masterKey.referenceBytes,
        masterKey.diversificationBytes, masterKey.contextBytes,
        masterKey.applicationId?.value ?: -1, masterKey.keySet?.value ?: -1,
    ), 16, "Malformed native provider AES-128 derivation result")
}

/** Calculate the documented eight-byte AES transaction MAC without card I/O. */
public fun calculateTransactionMacAes(
    transactionMacKey: ByteArray,
    transactionCounter: Long,
    uid: ByteArray,
    transactionInput: ByteArray,
): ByteArray {
    require(transactionMacKey.size == 16) { "An AES-128 transaction key must contain sixteen bytes" }
    require(transactionCounter in 0..0xFFFF_FFFFL) { "Transaction counter must fit uint32" }
    return exactOfflineResult(OfflineNative.transactionMacDirect(
        transactionMacKey, transactionCounter, uid, transactionInput,
    ), 8, "Malformed native transaction MAC result")
}

/** Resolve one provider transaction key and calculate its eight-byte transaction MAC. */
public fun calculateTransactionMacAes(
    transactionMacKey: KeySource.Provider,
    keyNumber: KeyNumber = KeyNumber(0),
    transactionCounter: Long,
    uid: ByteArray,
    transactionInput: ByteArray,
): ByteArray {
    require(transactionCounter in 0..0xFFFF_FFFFL) { "Transaction counter must fit uint32" }
    return exactOfflineResult(OfflineNative.transactionMacProvider(
        transactionMacKey.bridge, KeyScope.NATIVE.code, keyNumber.value,
        transactionMacKey.referenceBytes, transactionMacKey.diversificationBytes,
        transactionMacKey.contextBytes, transactionMacKey.applicationId?.value ?: -1,
        transactionMacKey.keySet?.value ?: -1, transactionCounter, uid, transactionInput,
    ), 8, "Malformed native provider transaction MAC result")
}

/** Verify a DESFire UID originality signature using the documented secp224r1 construction. */
public fun verifyOriginalityUidSignature(
    publicKey: ByteArray,
    uid: ByteArray,
    signature: ByteArray,
): Boolean = OfflineNative.verifyOriginality(publicKey, uid, signature)

/** Encrypt a delegated application default key into its exact 32-byte EncK record. */
public fun encryptDelegatedDefaultKeyAes(
    damEncryptionKey: ByteArray,
    applicationDefaultKey: ByteArray,
    applicationDefaultKeyVersion: Int,
): ByteArray {
    requireAesKey(damEncryptionKey)
    requireAesKey(applicationDefaultKey)
    require(applicationDefaultKeyVersion in 0..0xFF)
    return exactOfflineResult(
        OfflineNative.invoke(0, longArrayOf(applicationDefaultKeyVersion.toLong()),
            arrayOf(damEncryptionKey, applicationDefaultKey)),
        32, "Malformed native delegated encrypted-key result",
    )
}

/** Resolve DAMEncKey and encrypt a delegated application default key. */
public fun encryptDelegatedDefaultKeyAes(
    damEncryptionKey: KeySource.Provider,
    applicationDefaultKey: ByteArray,
    applicationDefaultKeyVersion: Int,
    providerKeyNumber: KeyNumber = KeyNumber(0),
): ByteArray {
    requireAesKey(applicationDefaultKey)
    require(applicationDefaultKeyVersion in 0..0xFF)
    return exactOfflineResult(
        providerInvoke(damEncryptionKey, providerKeyNumber, 0,
            longArrayOf(applicationDefaultKeyVersion.toLong()), arrayOf(applicationDefaultKey)),
        32, "Malformed native provider delegated encrypted-key result",
    )
}

/** Calculate the issuer MAC for one delegated application configuration and EncK. */
public fun calculateDelegatedApplicationMacAes(
    damMacKey: ByteArray,
    configuration: DelegatedApplication,
    encryptedDefaultKey: ByteArray,
): ByteArray {
    requireAesKey(damMacKey)
    return exactOfflineResult(
        OfflineNative.invoke(1, configurationNumbers(configuration),
            arrayOf(damMacKey, configuration.dfNameBytes, encryptedDefaultKey)),
        8, "Malformed native delegated application MAC result",
    )
}

/** Resolve DAMMACKey and calculate the issuer MAC for one delegated application. */
public fun calculateDelegatedApplicationMacAes(
    damMacKey: KeySource.Provider,
    configuration: DelegatedApplication,
    encryptedDefaultKey: ByteArray,
    providerKeyNumber: KeyNumber = KeyNumber(0),
): ByteArray = exactOfflineResult(
    providerInvoke(damMacKey, providerKeyNumber, 1, configurationNumbers(configuration),
        arrayOf(configuration.dfNameBytes, encryptedDefaultKey)),
    8, "Malformed native provider delegated application MAC result",
)

/** Calculate the issuer MAC authorizing deletion of one delegated application. */
public fun calculateDelegatedApplicationDeleteMacAes(
    damMacKey: ByteArray,
    applicationId: Int,
): ByteArray {
    requireAesKey(damMacKey)
    require(applicationId in 1..0xFFFFFF)
    return exactOfflineResult(
        OfflineNative.invoke(2, longArrayOf(applicationId.toLong()), arrayOf(damMacKey)),
        8, "Malformed native delegated deletion MAC result",
    )
}

/** Resolve DAMMACKey and calculate the delegated application deletion MAC. */
public fun calculateDelegatedApplicationDeleteMacAes(
    damMacKey: KeySource.Provider,
    applicationId: Int,
    providerKeyNumber: KeyNumber = KeyNumber(0),
): ByteArray {
    require(applicationId in 1..0xFFFFFF)
    return exactOfflineResult(
        providerInvoke(damMacKey, providerKeyNumber, 2,
            longArrayOf(applicationId.toLong()), arrayOf()),
        8, "Malformed native provider delegated deletion MAC result",
    )
}

/** Calculate the issuer MAC over an old and replacement delegated DF name. */
public fun calculateDelegatedConfigurationMacAes(
    damMacKey: ByteArray,
    oldDfName: ByteArray,
    newDfName: ByteArray,
): ByteArray {
    requireAesKey(damMacKey)
    return exactOfflineResult(
        OfflineNative.invoke(3, longArrayOf(), arrayOf(damMacKey, oldDfName, newDfName)),
        8, "Malformed native delegated configuration MAC result",
    )
}

/** Resolve DAMMACKey and calculate the delegated DF-name configuration MAC. */
public fun calculateDelegatedConfigurationMacAes(
    damMacKey: KeySource.Provider,
    oldDfName: ByteArray,
    newDfName: ByteArray,
    providerKeyNumber: KeyNumber = KeyNumber(0),
): ByteArray = exactOfflineResult(
    providerInvoke(damMacKey, providerKeyNumber, 3, longArrayOf(),
        arrayOf(oldDfName, newDfName)),
    8, "Malformed native provider delegated configuration MAC result",
)

/** Calculate the eight-byte AES MAC for one complete MIFARE Classic license record. */
public fun calculateMifareClassicLicenseMacAes(
    licenseMacKey: ByteArray,
    license: ByteArray,
    sectorSecrets: ByteArray,
): ByteArray {
    requireAesKey(licenseMacKey)
    return exactOfflineResult(
        OfflineNative.invoke(4, longArrayOf(),
            arrayOf(licenseMacKey, license, sectorSecrets)),
        8, "Malformed native MIFARE Classic license MAC result",
    )
}

/** Resolve MFCLicenseMACKey and calculate a MIFARE Classic license MAC. */
public fun calculateMifareClassicLicenseMacAes(
    licenseMacKey: KeySource.Provider,
    license: ByteArray,
    sectorSecrets: ByteArray,
    providerKeyNumber: KeyNumber = KeyNumber(0),
): ByteArray = exactOfflineResult(
    providerInvoke(licenseMacKey, providerKeyNumber, 4, longArrayOf(),
        arrayOf(license, sectorSecrets)),
    8, "Malformed native provider MIFARE Classic license MAC result",
)

/** Derive SesTMMACKey followed by SesTMENCKey into one 32-byte result. */
public fun deriveTransactionMacKeysAes(
    transactionKey: ByteArray,
    transactionCounter: Long,
    uid: ByteArray,
): ByteArray {
    requireAesKey(transactionKey)
    requireCounter(transactionCounter)
    return exactOfflineResult(
        OfflineNative.invoke(5, longArrayOf(transactionCounter), arrayOf(transactionKey, uid)),
        32, "Malformed native transaction session-key result",
    )
}

/** Resolve AppTransactionMACKey and derive both transaction session keys. */
public fun deriveTransactionMacKeysAes(
    transactionKey: KeySource.Provider,
    transactionCounter: Long,
    uid: ByteArray,
    providerKeyNumber: KeyNumber = KeyNumber(0),
): ByteArray {
    requireCounter(transactionCounter)
    return exactOfflineResult(
        providerInvoke(transactionKey, providerKeyNumber, 5,
            longArrayOf(transactionCounter), arrayOf(uid)),
        32, "Malformed native provider transaction session-key result",
    )
}

/** Calculate an eight-byte TMV from one already-derived SesTMMACKey. */
public fun calculateTransactionMacSessionAes(
    sessionMacKey: ByteArray,
    transactionInput: ByteArray,
): ByteArray {
    requireAesKey(sessionMacKey)
    return exactOfflineResult(
        OfflineNative.invoke(6, longArrayOf(), arrayOf(sessionMacKey, transactionInput)),
        8, "Malformed native session transaction MAC result",
    )
}

/** Verify a transaction MAC from the backend key and exact committed inputs. */
public fun verifyTransactionMacAes(
    transactionKey: ByteArray,
    transactionCounter: Long,
    uid: ByteArray,
    transactionInput: ByteArray,
    transactionMac: ByteArray,
): Boolean {
    requireAesKey(transactionKey)
    requireCounter(transactionCounter)
    return booleanResult(OfflineNative.invoke(7, longArrayOf(transactionCounter),
        arrayOf(transactionKey, uid, transactionInput, transactionMac)))
}

/** Resolve AppTransactionMACKey and verify a transaction MAC. */
public fun verifyTransactionMacAes(
    transactionKey: KeySource.Provider,
    transactionCounter: Long,
    uid: ByteArray,
    transactionInput: ByteArray,
    transactionMac: ByteArray,
    providerKeyNumber: KeyNumber = KeyNumber(0),
): Boolean {
    requireCounter(transactionCounter)
    return booleanResult(providerInvoke(transactionKey, providerKeyNumber, 7,
        longArrayOf(transactionCounter), arrayOf(uid, transactionInput, transactionMac)))
}

/** Decrypt one exact 16-byte EncTMRI with an already-derived SesTMENCKey. */
public fun decryptTransactionReaderIdAes(
    sessionEncryptionKey: ByteArray,
    encryptedReaderId: ByteArray,
): ByteArray {
    requireAesKey(sessionEncryptionKey)
    require(encryptedReaderId.size == 16) { "Encrypted transaction reader ID must be 16 bytes" }
    return exactOfflineResult(
        OfflineNative.invoke(8, longArrayOf(),
            arrayOf(sessionEncryptionKey, encryptedReaderId)),
        16, "Malformed native transaction reader-ID result",
    )
}

/** Encode the exact versioned delegated-application fields without native pointers. */
private fun configurationNumbers(configuration: DelegatedApplication): LongArray {
    val keySets = configuration.keySets
    return longArrayOf(
        configuration.applicationId.value.toLong(), configuration.keySettings.toLong(),
        configuration.numberOfKeys.toLong(), configuration.slot.toLong(),
        configuration.slotVersion.toLong(), configuration.quotaLimit.toLong(),
        if (configuration.isoFileIdentifiers) 1 else 0,
        configuration.keySettings3?.toLong() ?: -1,
        configuration.isoFileIdentifier?.value?.toLong() ?: -1,
        if (keySets != null) 1 else 0, keySets?.activeVersion?.toLong() ?: 0,
        keySets?.count?.toLong() ?: 0, keySets?.maximumKeySize?.toLong() ?: 0,
        keySets?.settings?.toLong() ?: 0,
    )
}

/** Invoke one provider helper with copied routing metadata. */
private fun providerInvoke(source: KeySource.Provider, keyNumber: KeyNumber, operation: Int,
    numbers: LongArray, data: Array<ByteArray>): ByteArray {
    return OfflineNative.invokeProvider(
        operation, source.bridge, KeyScope.NATIVE.code, keyNumber.value, source.referenceBytes,
        source.diversificationBytes, source.contextBytes, source.applicationId?.value ?: -1,
        source.keySet?.value ?: -1, numbers, data,
    )
}

/** Require one direct AES-128 key. */
private fun requireAesKey(key: ByteArray) {
    require(key.size == 16) { "An AES-128 key must contain sixteen bytes" }
}

/** Require an unsigned transaction counter. */
private fun requireCounter(counter: Long) {
    require(counter in 0..0xFFFF_FFFFL) { "Transaction counter must fit uint32" }
}

/** Require one exact fixed-width result from an offline native helper. */
internal fun exactOfflineResult(value: ByteArray, expected: Int, message: String): ByteArray {
    if (value.size != expected) {
        value.fill(0)
        throw MalformedNativeResultException(message)
    }
    return value
}

/** Decode the private one-byte JNI boolean representation. */
private fun booleanResult(value: ByteArray): Boolean {
    if (value.size != 1 || value[0].toInt() !in 0..1) {
        value.fill(0)
        throw MalformedNativeResultException("Malformed native boolean result")
    }
    return value[0].toInt() != 0
}

/** Private stateless JNI entry points; every returned array is independently owned. */
internal object OfflineNative {
    init { com.desfire.ev3.NativeRuntime.ensureLoaded() }

    @JvmStatic external fun deriveDirect(masterKey: ByteArray, diversification: ByteArray): ByteArray

    @JvmStatic external fun deriveProvider(
        provider: com.desfire.ev3.ProviderBridge,
        scope: Int,
        keyNumber: Int,
        reference: ByteArray,
        diversification: ByteArray,
        userContext: ByteArray,
        applicationId: Int,
        keySet: Int,
    ): ByteArray

    @JvmStatic external fun transactionMacDirect(
        key: ByteArray,
        transactionCounter: Long,
        uid: ByteArray,
        transactionInput: ByteArray,
    ): ByteArray

    @JvmStatic external fun transactionMacProvider(
        provider: com.desfire.ev3.ProviderBridge,
        scope: Int,
        keyNumber: Int,
        reference: ByteArray,
        diversification: ByteArray,
        userContext: ByteArray,
        applicationId: Int,
        keySet: Int,
        transactionCounter: Long,
        uid: ByteArray,
        transactionInput: ByteArray,
    ): ByteArray

    @JvmStatic external fun verifyOriginality(
        publicKey: ByteArray,
        uid: ByteArray,
        signature: ByteArray,
    ): Boolean

    @JvmStatic external fun invoke(
        operation: Int,
        numbers: LongArray,
        data: Array<ByteArray>,
    ): ByteArray

    @JvmStatic external fun invokeProvider(
        operation: Int,
        provider: com.desfire.ev3.ProviderBridge,
        scope: Int,
        keyNumber: Int,
        reference: ByteArray,
        diversification: ByteArray,
        userContext: ByteArray,
        applicationId: Int,
        keySet: Int,
        numbers: LongArray,
        data: Array<ByteArray>,
    ): ByteArray
}
