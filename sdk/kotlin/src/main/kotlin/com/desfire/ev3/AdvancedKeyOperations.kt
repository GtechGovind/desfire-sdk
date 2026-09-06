package com.desfire.ev3

/** Set the default application AES key without routing key bytes through generic dispatch. */
public fun BlockingCard.setDefaultAesKey(
    keySource: KeySource,
    version: Int,
    providerKeyNumber: KeyNumber = KeyNumber(0),
    timeoutMs: Long = 5_000,
) {
    require(version in 0..0xFF)
    require(timeoutMs in 1..0xFFFF_FFFFL)
    withExclusiveHandle { handle ->
        when (keySource) {
            is KeySource.Direct -> Native.setDefaultAesKeyDirect(
                handle, keySource.keyBytes, version, timeoutMs,
            )
            is KeySource.Derived -> Native.setDefaultAesKeyDerived(
                handle, keySource.masterKeyBytes, keySource.diversificationBytes, version,
                timeoutMs,
            )
            is KeySource.Provider -> Native.setDefaultAesKeyProvider(
                handle, providerKeyNumber.value, keySource.bridge, keySource.referenceBytes,
                keySource.diversificationBytes, keySource.contextBytes,
                keySource.applicationId?.value ?: -1, keySource.keySet?.value ?: -1,
                version, timeoutMs,
            )
        }
    }
}

/** Create a transaction-MAC file using a provider-resolved transaction key. */
public fun BlockingCard.createTransactionMacFile(
    file: FileNumber,
    accessRights: AccessRights,
    keySource: KeySource.Provider,
    version: Int,
    providerKeyNumber: KeyNumber = KeyNumber(0),
    timeoutMs: Long = 5_000,
) {
    require(version in 0..0xFF)
    require(timeoutMs in 1..0xFFFF_FFFFL)
    withExclusiveHandle { handle ->
        Native.createTransactionMacFileProvider(
            handle, file.value, accessRights.value, providerKeyNumber.value, keySource.bridge,
            keySource.referenceBytes, keySource.diversificationBytes, keySource.contextBytes,
            keySource.applicationId?.value ?: -1, keySource.keySet?.value ?: -1,
            version, timeoutMs,
        )
    }
}

/** Change one AES key using provider-resolved replacement and optional current keys. */
public fun BlockingCard.changeAesKey(
    number: KeyNumber,
    newKey: KeySource.Provider,
    version: Int,
    authenticatedKey: KeyNumber,
    oldKey: KeySource.Provider? = null,
    keySet: KeySetNumber? = null,
    piccMaster: Boolean = false,
    timeoutMs: Long = 5_000,
) {
    require(version in 0..0xFF)
    require(timeoutMs in 1..0xFFFF_FFFFL)
    withExclusiveHandle { handle ->
        Native.changeAesKeyProvider(
            handle, number.value, newKey.bridge, newKey.referenceBytes,
            newKey.diversificationBytes, newKey.contextBytes,
            newKey.applicationId?.value ?: -1, newKey.keySet?.value ?: -1, version,
            authenticatedKey.value, oldKey?.bridge, oldKey?.referenceBytes ?: byteArrayOf(),
            oldKey?.diversificationBytes ?: byteArrayOf(), oldKey?.contextBytes ?: byteArrayOf(),
            oldKey?.applicationId?.value ?: -1, oldKey?.keySet?.value ?: -1,
            keySet?.value ?: -1, piccMaster, timeoutMs,
        )
    }
}

/** Suspend-friendly default AES key update. */
public suspend fun Card.setDefaultAesKey(keySource: KeySource, version: Int,
    providerKeyNumber: KeyNumber = KeyNumber(0), timeoutMs: Long = 5_000): Unit =
    call { setDefaultAesKey(keySource, version, providerKeyNumber, timeoutMs) }

/** Suspend-friendly provider-backed transaction-MAC file creation. */
public suspend fun Card.createTransactionMacFile(file: FileNumber, accessRights: AccessRights,
    keySource: KeySource.Provider, version: Int,
    providerKeyNumber: KeyNumber = KeyNumber(0), timeoutMs: Long = 5_000): Unit =
    call { createTransactionMacFile(file, accessRights, keySource, version, providerKeyNumber,
        timeoutMs) }

/** Suspend-friendly provider-backed AES key change. */
public suspend fun Card.changeAesKey(number: KeyNumber, newKey: KeySource.Provider, version: Int,
    authenticatedKey: KeyNumber, oldKey: KeySource.Provider? = null,
    keySet: KeySetNumber? = null, piccMaster: Boolean = false,
    timeoutMs: Long = 5_000): Unit = call {
    changeAesKey(number, newKey, version, authenticatedKey, oldKey, keySet, piccMaster, timeoutMs)
}
