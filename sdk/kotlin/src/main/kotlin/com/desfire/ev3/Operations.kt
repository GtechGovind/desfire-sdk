// Typed base operations kept in stable JNI operation order.
package com.desfire.ev3

import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Reset; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.reset(
): Unit {
    val result = invoke(
        0,
        longArrayOf(
        ),
        arrayOf()
    )
    requireEmptyNativeResult(result, "Unexpected native mutation payload")
}

/** Cancel; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.cancel(
): Unit {
    val result = invoke(
        1,
        longArrayOf(
        ),
        arrayOf()
    )
    requireEmptyNativeResult(result, "Unexpected native mutation payload")
}

/** Notify state change; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.notifyStateChange(
): Unit {
    val result = invoke(
        2,
        longArrayOf(
        ),
        arrayOf()
    )
    requireEmptyNativeResult(result, "Unexpected native mutation payload")
}

/** Get version; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.getVersion(
    timeoutMs: Long = 5000,
): ByteArray {
    val result = invoke(
        3,
        longArrayOf(
            timeoutMs,
        ),
        arrayOf()
    )
    requireNativeResultSize(result, 28, "Malformed native version result")
    return result
}

/** Free memory; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.freeMemory(
    timeoutMs: Long = 5000,
): Long {
    val result = invoke(
        4,
        longArrayOf(
            timeoutMs,
        ),
        arrayOf()
    )
    requireNativeResultSize(result, 4, "Malformed native scalar result")
    return (ByteBuffer.wrap(result).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL)
}

/** Select application; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.selectApplication(
    aid: ApplicationId,
    timeoutMs: Long = 5000,
): Unit {
    val result = invoke(
        5,
        longArrayOf(
            aid.value.toLong(),
            timeoutMs,
        ),
        arrayOf()
    )
    requireEmptyNativeResult(result, "Unexpected native mutation payload")
}

/** File ids; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.fileIds(
    timeoutMs: Long = 5000,
): ByteArray {
    val result = invoke(
        6,
        longArrayOf(
            timeoutMs,
        ),
        arrayOf()
    )
    return result
}

/** Application ids; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.applicationIds(
    timeoutMs: Long = 5000,
): ByteArray {
    val result = invoke(
        8,
        longArrayOf(
            timeoutMs,
        ),
        arrayOf()
    )
    return result
}

/** Iso file ids; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.isoFileIds(
    timeoutMs: Long = 5000,
): ByteArray {
    val result = invoke(
        9,
        longArrayOf(
            timeoutMs,
        ),
        arrayOf()
    )
    return result
}

/** Get key settings; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.getKeySettings(
    timeoutMs: Long = 5000,
): ByteArray {
    val result = invoke(
        10,
        longArrayOf(
            timeoutMs,
        ),
        arrayOf()
    )
    return result
}

/** Get key set versions; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.getKeySetVersions(
    timeoutMs: Long = 5000,
): ByteArray {
    val result = invoke(
        11,
        longArrayOf(
            timeoutMs,
        ),
        arrayOf()
    )
    return result
}

/** Get card uid; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.getCardUid(
    timeoutMs: Long = 5000,
): ByteArray {
    val result = invoke(
        12,
        longArrayOf(
            timeoutMs,
        ),
        arrayOf()
    )
    return result
}

/** Read originality signature; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.readOriginalitySignature(
    timeoutMs: Long = 5000,
): ByteArray {
    val result = invoke(
        13,
        longArrayOf(
            timeoutMs,
        ),
        arrayOf()
    )
    requireNativeResultSize(result, 56, "Malformed native originality-signature result")
    return result
}

/** Abort transaction; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.abortTransaction(
    timeoutMs: Long = 5000,
): Unit {
    val result = invoke(
        14,
        longArrayOf(
            timeoutMs,
        ),
        arrayOf()
    )
    requireEmptyNativeResult(result, "Unexpected native mutation payload")
}

/** Format picc; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.formatPicc(
    timeoutMs: Long = 5000,
): Unit {
    val result = invoke(
        15,
        longArrayOf(
            timeoutMs,
        ),
        arrayOf()
    )
    requireEmptyNativeResult(result, "Unexpected native mutation payload")
}

/** Delete file; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.deleteFile(
    file: FileNumber,
    timeoutMs: Long = 5000,
): Unit {
    val result = invoke(
        16,
        longArrayOf(
            file.value.toLong(),
            timeoutMs,
        ),
        arrayOf()
    )
    requireEmptyNativeResult(result, "Unexpected native mutation payload")
}

/** Get file settings; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.getFileSettings(
    file: FileNumber,
    timeoutMs: Long = 5000,
): ByteArray {
    val result = invoke(
        17,
        longArrayOf(
            file.value.toLong(),
            timeoutMs,
        ),
        arrayOf()
    )
    return result
}

/** Clear record file; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.clearRecordFile(
    file: FileNumber,
    timeoutMs: Long = 5000,
): Unit {
    val result = invoke(
        18,
        longArrayOf(
            file.value.toLong(),
            timeoutMs,
        ),
        arrayOf()
    )
    requireEmptyNativeResult(result, "Unexpected native mutation payload")
}

/** Get file counters; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.getFileCounters(
    file: FileNumber,
    communication: Communication,
    timeoutMs: Long = 5000,
): ByteArray {
    val result = invoke(
        19,
        longArrayOf(
            file.value.toLong(),
            communication.value.toLong(),
            timeoutMs,
        ),
        arrayOf()
    )
    requireNativeResultSize(result, 5, "Malformed native file-counter result")
    return result
}

/** Delete application; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.deleteApplication(
    aid: ApplicationId,
    timeoutMs: Long = 5000,
): Unit {
    val result = invoke(
        20,
        longArrayOf(
            aid.value.toLong(),
            timeoutMs,
        ),
        arrayOf()
    )
    requireEmptyNativeResult(result, "Unexpected native mutation payload")
}

/** Change key settings; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.changeKeySettings(
    settings: Long,
    timeoutMs: Long = 5000,
): Unit {
    val result = invoke(
        21,
        longArrayOf(
            settings,
            timeoutMs,
        ),
        arrayOf()
    )
    requireEmptyNativeResult(result, "Unexpected native mutation payload")
}

/** Get key version; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.getKeyVersion(
    number: KeyNumber,
    keySet: Int,
    timeoutMs: Long = 5000,
): ByteArray {
    val result = invoke(
        22,
        longArrayOf(
            number.value.toLong(),
            keySet.toLong(),
            timeoutMs,
        ),
        arrayOf()
    )
    requireNativeResultSize(result, 1, "Malformed native key-version result")
    return result
}

/** Initialize key set; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.initializeKeySet(
    keySet: Long,
    timeoutMs: Long = 5000,
): Unit {
    val result = invoke(
        23,
        longArrayOf(
            keySet,
            timeoutMs,
        ),
        arrayOf()
    )
    requireEmptyNativeResult(result, "Unexpected native mutation payload")
}

/** Roll key set; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.rollKeySet(
    keySet: Long,
    timeoutMs: Long = 5000,
): Unit {
    val result = invoke(
        24,
        longArrayOf(
            keySet,
            timeoutMs,
        ),
        arrayOf()
    )
    requireEmptyNativeResult(result, "Unexpected native mutation payload")
}

/** Finalize key set; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.finalizeKeySet(
    keySet: Long,
    version: Long,
    timeoutMs: Long = 5000,
): Unit {
    val result = invoke(
        25,
        longArrayOf(
            keySet,
            version,
            timeoutMs,
        ),
        arrayOf()
    )
    requireEmptyNativeResult(result, "Unexpected native mutation payload")
}

/** Read data; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.readData(
    file: FileNumber,
    offset: ByteOffset,
    length: Long,
    communication: Communication,
    timeoutMs: Long = 5000,
): ByteArray {
    val result = invoke(
        26,
        longArrayOf(
            file.value.toLong(),
            offset.value.toLong(),
            length,
            communication.value.toLong(),
            timeoutMs,
        ),
        arrayOf()
    )
    return result
}

/** Write data; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.writeData(
    file: FileNumber,
    offset: ByteOffset,
    data: ByteArray,
    communication: Communication,
    timeoutMs: Long = 5000,
): Unit {
    val result = invoke(
        27,
        longArrayOf(
            file.value.toLong(),
            offset.value.toLong(),
            communication.value.toLong(),
            timeoutMs,
        ),
        arrayOf(data)
    )
    requireEmptyNativeResult(result, "Unexpected native mutation payload")
}

/** Write record; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.writeRecord(
    file: FileNumber,
    offset: ByteOffset,
    data: ByteArray,
    communication: Communication,
    timeoutMs: Long = 5000,
): Unit {
    val result = invoke(
        28,
        longArrayOf(
            file.value.toLong(),
            offset.value.toLong(),
            communication.value.toLong(),
            timeoutMs,
        ),
        arrayOf(data)
    )
    requireEmptyNativeResult(result, "Unexpected native mutation payload")
}

/** Read records; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.readRecords(
    file: FileNumber,
    first: Long,
    count: Long,
    communication: Communication,
    timeoutMs: Long = 5000,
): ByteArray {
    val result = invoke(
        29,
        longArrayOf(
            file.value.toLong(),
            first,
            count,
            communication.value.toLong(),
            timeoutMs,
        ),
        arrayOf()
    )
    return result
}

/** Update record; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.updateRecord(
    file: FileNumber,
    record: Long,
    offset: ByteOffset,
    data: ByteArray,
    communication: Communication,
    timeoutMs: Long = 5000,
): Unit {
    val result = invoke(
        30,
        longArrayOf(
            file.value.toLong(),
            record,
            offset.value.toLong(),
            communication.value.toLong(),
            timeoutMs,
        ),
        arrayOf(data)
    )
    requireEmptyNativeResult(result, "Unexpected native mutation payload")
}

/** Credit; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.credit(
    file: FileNumber,
    amount: Long,
    communication: Communication,
    timeoutMs: Long = 5000,
): Unit {
    val result = invoke(
        31,
        longArrayOf(
            file.value.toLong(),
            amount,
            communication.value.toLong(),
            timeoutMs,
        ),
        arrayOf()
    )
    requireEmptyNativeResult(result, "Unexpected native mutation payload")
}

/** Debit; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.debit(
    file: FileNumber,
    amount: Long,
    communication: Communication,
    timeoutMs: Long = 5000,
): Unit {
    val result = invoke(
        32,
        longArrayOf(
            file.value.toLong(),
            amount,
            communication.value.toLong(),
            timeoutMs,
        ),
        arrayOf()
    )
    requireEmptyNativeResult(result, "Unexpected native mutation payload")
}

/** Limited credit; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.limitedCredit(
    file: FileNumber,
    amount: Long,
    communication: Communication,
    timeoutMs: Long = 5000,
): Unit {
    val result = invoke(
        33,
        longArrayOf(
            file.value.toLong(),
            amount,
            communication.value.toLong(),
            timeoutMs,
        ),
        arrayOf()
    )
    requireEmptyNativeResult(result, "Unexpected native mutation payload")
}

/** Get value; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.getValue(
    file: FileNumber,
    communication: Communication,
    timeoutMs: Long = 5000,
): Int {
    val result = invoke(
        34,
        longArrayOf(
            file.value.toLong(),
            communication.value.toLong(),
            timeoutMs,
        ),
        arrayOf()
    )
    requireNativeResultSize(result, 4, "Malformed native scalar result")
    return ByteBuffer.wrap(result).order(ByteOrder.LITTLE_ENDIAN).int
}

/** Commit transaction; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.commitTransaction(
    returnMac: Boolean,
    timeoutMs: Long = 5000,
): ByteArray {
    val result = invoke(
        35,
        longArrayOf(
            if (returnMac) 1L else 0L,
            timeoutMs,
        ),
        arrayOf()
    )
    requireNativeResultSize(
        result,
        if (returnMac) 12 else 0,
        "Malformed native transaction-commit result",
    )
    return result
}

/** Commit reader id; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.commitReaderId(
    readerId: ByteArray,
    timeoutMs: Long = 5000,
): ByteArray {
    val result = invoke(
        36,
        longArrayOf(
            timeoutMs,
        ),
        arrayOf(readerId)
    )
    requireNativeResultSize(result, 16, "Malformed native committed reader-ID result")
    return result
}

/** Create application; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.createApplication(
    aid: ApplicationId,
    keySettings: Long,
    keyCount: Long,
    isoId: Int,
    dfName: ByteArray,
    timeoutMs: Long = 5000,
): Unit {
    val result = invoke(
        37,
        longArrayOf(
            aid.value.toLong(),
            keySettings,
            keyCount,
            isoId.toLong(),
            timeoutMs,
        ),
        arrayOf(dfName)
    )
    requireEmptyNativeResult(result, "Unexpected native mutation payload")
}

/** Create data file; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.createDataFile(
    file: FileNumber,
    length: Long,
    communication: Communication,
    accessRights: AccessRights,
    isoId: Int,
    backup: Boolean,
    timeoutMs: Long = 5000,
): Unit {
    val result = invoke(
        38,
        longArrayOf(
            file.value.toLong(),
            length,
            communication.value.toLong(),
            accessRights.value.toLong(),
            isoId.toLong(),
            if (backup) 1L else 0L,
            timeoutMs,
        ),
        arrayOf()
    )
    requireEmptyNativeResult(result, "Unexpected native mutation payload")
}

/** Create value file; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.createValueFile(
    file: FileNumber,
    lowerLimit: Int,
    upperLimit: Int,
    initialValue: Int,
    communication: Communication,
    accessRights: AccessRights,
    limitedCredit: Boolean,
    freeGetValue: Boolean,
    timeoutMs: Long = 5000,
): Unit {
    val result = invoke(
        39,
        longArrayOf(
            file.value.toLong(),
            lowerLimit.toLong(),
            upperLimit.toLong(),
            initialValue.toLong(),
            communication.value.toLong(),
            accessRights.value.toLong(),
            if (limitedCredit) 1L else 0L,
            if (freeGetValue) 1L else 0L,
            timeoutMs,
        ),
        arrayOf()
    )
    requireEmptyNativeResult(result, "Unexpected native mutation payload")
}

/** Create record file; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.createRecordFile(
    file: FileNumber,
    recordSize: Long,
    maximumRecords: Long,
    communication: Communication,
    accessRights: AccessRights,
    isoId: Int,
    cyclic: Boolean,
    timeoutMs: Long = 5000,
): Unit {
    val result = invoke(
        40,
        longArrayOf(
            file.value.toLong(),
            recordSize,
            maximumRecords,
            communication.value.toLong(),
            accessRights.value.toLong(),
            isoId.toLong(),
            if (cyclic) 1L else 0L,
            timeoutMs,
        ),
        arrayOf()
    )
    requireEmptyNativeResult(result, "Unexpected native mutation payload")
}

/** Change file settings; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.changeFileSettings(
    file: FileNumber,
    communication: Communication,
    accessRights: AccessRights,
    commandCommunication: Communication,
    timeoutMs: Long = 5000,
): Unit {
    val result = invoke(
        41,
        longArrayOf(
            file.value.toLong(),
            communication.value.toLong(),
            accessRights.value.toLong(),
            commandCommunication.value.toLong(),
            timeoutMs,
        ),
        arrayOf()
    )
    requireEmptyNativeResult(result, "Unexpected native mutation payload")
}

/** Create transaction mac file; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.createTransactionMacFile(
    file: FileNumber,
    accessRights: AccessRights,
    key: ByteArray,
    version: Long,
    timeoutMs: Long = 5000,
): Unit {
    val result = invoke(
        42,
        longArrayOf(
            file.value.toLong(),
            accessRights.value.toLong(),
            version,
            timeoutMs,
        ),
        arrayOf(key)
    )
    requireEmptyNativeResult(result, "Unexpected native mutation payload")
}

/** Change aes key; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.changeAesKey(
    number: KeyNumber,
    newKey: ByteArray,
    version: Long,
    authenticatedKey: Boolean,
    oldKey: ByteArray,
    keySet: Int,
    piccMaster: Boolean,
    timeoutMs: Long = 5000,
): Unit {
    val result = invoke(
        43,
        longArrayOf(
            number.value.toLong(),
            version,
            if (authenticatedKey) 1L else 0L,
            keySet.toLong(),
            if (piccMaster) 1L else 0L,
            timeoutMs,
        ),
        arrayOf(newKey, oldKey)
    )
    requireEmptyNativeResult(result, "Unexpected native mutation payload")
}

/** Iso select file; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.isoSelectFile(
    identifier: IsoFileIdentifier,
    selection: IsoFileSelection,
    response: IsoSelectionResponse,
    timeoutMs: Long = 5000,
): ByteArray {
    val result = invoke(
        44,
        longArrayOf(
            identifier.value.toLong(),
            selection.value.toLong(),
            response.value.toLong(),
            timeoutMs,
        ),
        arrayOf()
    )
    return result
}

/** Iso select df name; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.isoSelectDfName(
    name: ByteArray,
    response: IsoSelectionResponse,
    timeoutMs: Long = 5000,
): ByteArray {
    val result = invoke(
        45,
        longArrayOf(
            response.value.toLong(),
            timeoutMs,
        ),
        arrayOf(name)
    )
    return result
}

/** Iso read binary; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.isoReadBinary(
    shortIdentifier: Int,
    offset: ByteOffset,
    length: Long,
    timeoutMs: Long = 5000,
): ByteArray {
    val result = invoke(
        46,
        longArrayOf(
            shortIdentifier.toLong(),
            offset.value.toLong(),
            length,
            timeoutMs,
        ),
        arrayOf()
    )
    return result
}

/** Iso update binary; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.isoUpdateBinary(
    shortIdentifier: Int,
    offset: ByteOffset,
    data: ByteArray,
    timeoutMs: Long = 5000,
): ByteArray {
    val result = invoke(
        47,
        longArrayOf(
            shortIdentifier.toLong(),
            offset.value.toLong(),
            timeoutMs,
        ),
        arrayOf(data)
    )
    return result
}

/** Iso read records; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.isoReadRecords(
    record: Long,
    shortIdentifier: Long,
    selection: IsoRecordSelection,
    length: Long,
    timeoutMs: Long = 5000,
): ByteArray {
    val result = invoke(
        48,
        longArrayOf(
            record,
            shortIdentifier,
            selection.value.toLong(),
            length,
            timeoutMs,
        ),
        arrayOf()
    )
    return result
}

/** Iso append record; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.isoAppendRecord(
    shortIdentifier: Long,
    data: ByteArray,
    timeoutMs: Long = 5000,
): ByteArray {
    val result = invoke(
        49,
        longArrayOf(
            shortIdentifier,
            timeoutMs,
        ),
        arrayOf(data)
    )
    return result
}

/** Iso get challenge; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.isoGetChallenge(
    length: Long,
    timeoutMs: Long = 5000,
): ByteArray {
    val result = invoke(
        50,
        longArrayOf(
            length,
            timeoutMs,
        ),
        arrayOf()
    )
    return result
}

/** Iso external authenticate; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.isoExternalAuthenticate(
    number: KeyNumber,
    application: Boolean,
    algorithm: IsoAlgorithm,
    data: ByteArray,
    timeoutMs: Long = 5000,
): ByteArray {
    val result = invoke(
        51,
        longArrayOf(
            number.value.toLong(),
            if (application) 1L else 0L,
            algorithm.value.toLong(),
            timeoutMs,
        ),
        arrayOf(data)
    )
    return result
}

/** Iso internal authenticate; preserves code, outcome and device status.
 * Byte arrays are copied for the call; keys are not retained. Never retries card operations. */
fun BlockingCard.isoInternalAuthenticate(
    number: KeyNumber,
    application: Boolean,
    algorithm: IsoAlgorithm,
    data: ByteArray,
    timeoutMs: Long = 5000,
): ByteArray {
    val result = invoke(
        52,
        longArrayOf(
            number.value.toLong(),
            if (application) 1L else 0L,
            algorithm.value.toLong(),
            timeoutMs,
        ),
        arrayOf(data)
    )
    return result
}
