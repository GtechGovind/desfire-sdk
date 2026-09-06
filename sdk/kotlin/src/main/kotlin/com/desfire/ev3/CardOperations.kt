// Suspend-first counterparts to the stable typed base operations.
package com.desfire.ev3

/** Suspend reset; underlying I/O owns its delivery outcome. */
suspend fun Card.reset(
): Unit =
    call {
        reset(
        )
    }

/** Request cancellation immediately without waiting behind the card's FIFO operation queue. */
public fun Card.cancel(): Unit = requestCancellation()

/** Suspend notify state change; underlying I/O owns its delivery outcome. */
suspend fun Card.notifyStateChange(
): Unit =
    call {
        notifyStateChange(
        )
    }

/** Suspend get version; underlying I/O owns its delivery outcome. */
suspend fun Card.getVersion(
    timeoutMs: Long = 5000,
): ByteArray =
    call {
        getVersion(
            timeoutMs,
        )
    }

/** Suspend free memory; underlying I/O owns its delivery outcome. */
suspend fun Card.freeMemory(
    timeoutMs: Long = 5000,
): Long =
    call {
        freeMemory(
            timeoutMs,
        )
    }

/** Suspend select application; underlying I/O owns its delivery outcome. */
suspend fun Card.selectApplication(
    aid: ApplicationId,
    timeoutMs: Long = 5000,
): Unit =
    call {
        selectApplication(
            aid,
            timeoutMs,
        )
    }

/** Suspend file ids; underlying I/O owns its delivery outcome. */
suspend fun Card.fileIds(
    timeoutMs: Long = 5000,
): ByteArray =
    call {
        fileIds(
            timeoutMs,
        )
    }

/** Suspend application ids; underlying I/O owns its delivery outcome. */
suspend fun Card.applicationIds(
    timeoutMs: Long = 5000,
): ByteArray =
    call {
        applicationIds(
            timeoutMs,
        )
    }

/** Suspend iso file ids; underlying I/O owns its delivery outcome. */
suspend fun Card.isoFileIds(
    timeoutMs: Long = 5000,
): ByteArray =
    call {
        isoFileIds(
            timeoutMs,
        )
    }

/** Suspend get key settings; underlying I/O owns its delivery outcome. */
suspend fun Card.getKeySettings(
    timeoutMs: Long = 5000,
): ByteArray =
    call {
        getKeySettings(
            timeoutMs,
        )
    }

/** Suspend get key set versions; underlying I/O owns its delivery outcome. */
suspend fun Card.getKeySetVersions(
    timeoutMs: Long = 5000,
): ByteArray =
    call {
        getKeySetVersions(
            timeoutMs,
        )
    }

/** Suspend get card uid; underlying I/O owns its delivery outcome. */
suspend fun Card.getCardUid(
    timeoutMs: Long = 5000,
): ByteArray =
    call {
        getCardUid(
            timeoutMs,
        )
    }

/** Suspend read originality signature; underlying I/O owns its delivery outcome. */
suspend fun Card.readOriginalitySignature(
    timeoutMs: Long = 5000,
): ByteArray =
    call {
        readOriginalitySignature(
            timeoutMs,
        )
    }

/** Suspend abort transaction; underlying I/O owns its delivery outcome. */
suspend fun Card.abortTransaction(
    timeoutMs: Long = 5000,
): Unit =
    call {
        abortTransaction(
            timeoutMs,
        )
    }

/** Suspend format picc; underlying I/O owns its delivery outcome. */
suspend fun Card.formatPicc(
    timeoutMs: Long = 5000,
): Unit =
    call {
        formatPicc(
            timeoutMs,
        )
    }

/** Suspend delete file; underlying I/O owns its delivery outcome. */
suspend fun Card.deleteFile(
    file: FileNumber,
    timeoutMs: Long = 5000,
): Unit =
    call {
        deleteFile(
            file,
            timeoutMs,
        )
    }

/** Suspend get file settings; underlying I/O owns its delivery outcome. */
suspend fun Card.getFileSettings(
    file: FileNumber,
    timeoutMs: Long = 5000,
): ByteArray =
    call {
        getFileSettings(
            file,
            timeoutMs,
        )
    }

/** Suspend clear record file; underlying I/O owns its delivery outcome. */
suspend fun Card.clearRecordFile(
    file: FileNumber,
    timeoutMs: Long = 5000,
): Unit =
    call {
        clearRecordFile(
            file,
            timeoutMs,
        )
    }

/** Suspend get file counters; underlying I/O owns its delivery outcome. */
suspend fun Card.getFileCounters(
    file: FileNumber,
    communication: Communication,
    timeoutMs: Long = 5000,
): ByteArray =
    call {
        getFileCounters(
            file,
            communication,
            timeoutMs,
        )
    }

/** Suspend delete application; underlying I/O owns its delivery outcome. */
suspend fun Card.deleteApplication(
    aid: ApplicationId,
    timeoutMs: Long = 5000,
): Unit =
    call {
        deleteApplication(
            aid,
            timeoutMs,
        )
    }

/** Suspend change key settings; underlying I/O owns its delivery outcome. */
suspend fun Card.changeKeySettings(
    settings: Long,
    timeoutMs: Long = 5000,
): Unit =
    call {
        changeKeySettings(
            settings,
            timeoutMs,
        )
    }

/** Suspend get key version; underlying I/O owns its delivery outcome. */
suspend fun Card.getKeyVersion(
    number: KeyNumber,
    keySet: Int,
    timeoutMs: Long = 5000,
): ByteArray =
    call {
        getKeyVersion(
            number,
            keySet,
            timeoutMs,
        )
    }

/** Suspend initialize key set; underlying I/O owns its delivery outcome. */
suspend fun Card.initializeKeySet(
    keySet: Long,
    timeoutMs: Long = 5000,
): Unit =
    call {
        initializeKeySet(
            keySet,
            timeoutMs,
        )
    }

/** Suspend roll key set; underlying I/O owns its delivery outcome. */
suspend fun Card.rollKeySet(
    keySet: Long,
    timeoutMs: Long = 5000,
): Unit =
    call {
        rollKeySet(
            keySet,
            timeoutMs,
        )
    }

/** Suspend finalize key set; underlying I/O owns its delivery outcome. */
suspend fun Card.finalizeKeySet(
    keySet: Long,
    version: Long,
    timeoutMs: Long = 5000,
): Unit =
    call {
        finalizeKeySet(
            keySet,
            version,
            timeoutMs,
        )
    }

/** Suspend read data; underlying I/O owns its delivery outcome. */
suspend fun Card.readData(
    file: FileNumber,
    offset: ByteOffset,
    length: Long,
    communication: Communication,
    timeoutMs: Long = 5000,
): ByteArray =
    call {
        readData(
            file,
            offset,
            length,
            communication,
            timeoutMs,
        )
    }

/** Suspend write data; underlying I/O owns its delivery outcome. */
suspend fun Card.writeData(
    file: FileNumber,
    offset: ByteOffset,
    data: ByteArray,
    communication: Communication,
    timeoutMs: Long = 5000,
): Unit =
    call {
        writeData(
            file,
            offset,
            data,
            communication,
            timeoutMs,
        )
    }

/** Suspend write record; underlying I/O owns its delivery outcome. */
suspend fun Card.writeRecord(
    file: FileNumber,
    offset: ByteOffset,
    data: ByteArray,
    communication: Communication,
    timeoutMs: Long = 5000,
): Unit =
    call {
        writeRecord(
            file,
            offset,
            data,
            communication,
            timeoutMs,
        )
    }

/** Suspend read records; underlying I/O owns its delivery outcome. */
suspend fun Card.readRecords(
    file: FileNumber,
    first: Long,
    count: Long,
    communication: Communication,
    timeoutMs: Long = 5000,
): ByteArray =
    call {
        readRecords(
            file,
            first,
            count,
            communication,
            timeoutMs,
        )
    }

/** Suspend update record; underlying I/O owns its delivery outcome. */
suspend fun Card.updateRecord(
    file: FileNumber,
    record: Long,
    offset: ByteOffset,
    data: ByteArray,
    communication: Communication,
    timeoutMs: Long = 5000,
): Unit =
    call {
        updateRecord(
            file,
            record,
            offset,
            data,
            communication,
            timeoutMs,
        )
    }

/** Suspend credit; underlying I/O owns its delivery outcome. */
suspend fun Card.credit(
    file: FileNumber,
    amount: Long,
    communication: Communication,
    timeoutMs: Long = 5000,
): Unit =
    call {
        credit(
            file,
            amount,
            communication,
            timeoutMs,
        )
    }

/** Suspend debit; underlying I/O owns its delivery outcome. */
suspend fun Card.debit(
    file: FileNumber,
    amount: Long,
    communication: Communication,
    timeoutMs: Long = 5000,
): Unit =
    call {
        debit(
            file,
            amount,
            communication,
            timeoutMs,
        )
    }

/** Suspend limited credit; underlying I/O owns its delivery outcome. */
suspend fun Card.limitedCredit(
    file: FileNumber,
    amount: Long,
    communication: Communication,
    timeoutMs: Long = 5000,
): Unit =
    call {
        limitedCredit(
            file,
            amount,
            communication,
            timeoutMs,
        )
    }

/** Suspend get value; underlying I/O owns its delivery outcome. */
suspend fun Card.getValue(
    file: FileNumber,
    communication: Communication,
    timeoutMs: Long = 5000,
): Int =
    call {
        getValue(
            file,
            communication,
            timeoutMs,
        )
    }

/** Suspend commit transaction; underlying I/O owns its delivery outcome. */
suspend fun Card.commitTransaction(
    returnMac: Boolean,
    timeoutMs: Long = 5000,
): ByteArray =
    call {
        commitTransaction(
            returnMac,
            timeoutMs,
        )
    }

/** Suspend commit reader id; underlying I/O owns its delivery outcome. */
suspend fun Card.commitReaderId(
    readerId: ByteArray,
    timeoutMs: Long = 5000,
): ByteArray =
    call {
        commitReaderId(
            readerId,
            timeoutMs,
        )
    }

/** Suspend create application; underlying I/O owns its delivery outcome. */
suspend fun Card.createApplication(
    aid: ApplicationId,
    keySettings: Long,
    keyCount: Long,
    isoId: Int,
    dfName: ByteArray,
    timeoutMs: Long = 5000,
): Unit =
    call {
        createApplication(
            aid,
            keySettings,
            keyCount,
            isoId,
            dfName,
            timeoutMs,
        )
    }

/** Suspend create data file; underlying I/O owns its delivery outcome. */
suspend fun Card.createDataFile(
    file: FileNumber,
    length: Long,
    communication: Communication,
    accessRights: AccessRights,
    isoId: Int,
    backup: Boolean,
    timeoutMs: Long = 5000,
): Unit =
    call {
        createDataFile(
            file,
            length,
            communication,
            accessRights,
            isoId,
            backup,
            timeoutMs,
        )
    }

/** Suspend create value file; underlying I/O owns its delivery outcome. */
suspend fun Card.createValueFile(
    file: FileNumber,
    lowerLimit: Int,
    upperLimit: Int,
    initialValue: Int,
    communication: Communication,
    accessRights: AccessRights,
    limitedCredit: Boolean,
    freeGetValue: Boolean,
    timeoutMs: Long = 5000,
): Unit =
    call {
        createValueFile(
            file,
            lowerLimit,
            upperLimit,
            initialValue,
            communication,
            accessRights,
            limitedCredit,
            freeGetValue,
            timeoutMs,
        )
    }

/** Suspend create record file; underlying I/O owns its delivery outcome. */
suspend fun Card.createRecordFile(
    file: FileNumber,
    recordSize: Long,
    maximumRecords: Long,
    communication: Communication,
    accessRights: AccessRights,
    isoId: Int,
    cyclic: Boolean,
    timeoutMs: Long = 5000,
): Unit =
    call {
        createRecordFile(
            file,
            recordSize,
            maximumRecords,
            communication,
            accessRights,
            isoId,
            cyclic,
            timeoutMs,
        )
    }

/** Suspend change file settings; underlying I/O owns its delivery outcome. */
suspend fun Card.changeFileSettings(
    file: FileNumber,
    communication: Communication,
    accessRights: AccessRights,
    commandCommunication: Communication,
    timeoutMs: Long = 5000,
): Unit =
    call {
        changeFileSettings(
            file,
            communication,
            accessRights,
            commandCommunication,
            timeoutMs,
        )
    }

/** Suspend create transaction mac file; underlying I/O owns its delivery outcome. */
suspend fun Card.createTransactionMacFile(
    file: FileNumber,
    accessRights: AccessRights,
    key: ByteArray,
    version: Long,
    timeoutMs: Long = 5000,
): Unit =
    call {
        createTransactionMacFile(
            file,
            accessRights,
            key,
            version,
            timeoutMs,
        )
    }

/** Suspend change aes key; underlying I/O owns its delivery outcome. */
suspend fun Card.changeAesKey(
    number: KeyNumber,
    newKey: ByteArray,
    version: Long,
    authenticatedKey: Boolean,
    oldKey: ByteArray,
    keySet: Int,
    piccMaster: Boolean,
    timeoutMs: Long = 5000,
): Unit =
    call {
        changeAesKey(
            number,
            newKey,
            version,
            authenticatedKey,
            oldKey,
            keySet,
            piccMaster,
            timeoutMs,
        )
    }

/** Suspend iso select file; underlying I/O owns its delivery outcome. */
suspend fun Card.isoSelectFile(
    identifier: IsoFileIdentifier,
    selection: IsoFileSelection,
    response: IsoSelectionResponse,
    timeoutMs: Long = 5000,
): ByteArray =
    call {
        isoSelectFile(
            identifier,
            selection,
            response,
            timeoutMs,
        )
    }

/** Suspend iso select df name; underlying I/O owns its delivery outcome. */
suspend fun Card.isoSelectDfName(
    name: ByteArray,
    response: IsoSelectionResponse,
    timeoutMs: Long = 5000,
): ByteArray =
    call {
        isoSelectDfName(
            name,
            response,
            timeoutMs,
        )
    }

/** Suspend iso read binary; underlying I/O owns its delivery outcome. */
suspend fun Card.isoReadBinary(
    shortIdentifier: Int,
    offset: ByteOffset,
    length: Long,
    timeoutMs: Long = 5000,
): ByteArray =
    call {
        isoReadBinary(
            shortIdentifier,
            offset,
            length,
            timeoutMs,
        )
    }

/** Suspend iso update binary; underlying I/O owns its delivery outcome. */
suspend fun Card.isoUpdateBinary(
    shortIdentifier: Int,
    offset: ByteOffset,
    data: ByteArray,
    timeoutMs: Long = 5000,
): ByteArray =
    call {
        isoUpdateBinary(
            shortIdentifier,
            offset,
            data,
            timeoutMs,
        )
    }

/** Suspend iso read records; underlying I/O owns its delivery outcome. */
suspend fun Card.isoReadRecords(
    record: Long,
    shortIdentifier: Long,
    selection: IsoRecordSelection,
    length: Long,
    timeoutMs: Long = 5000,
): ByteArray =
    call {
        isoReadRecords(
            record,
            shortIdentifier,
            selection,
            length,
            timeoutMs,
        )
    }

/** Suspend iso append record; underlying I/O owns its delivery outcome. */
suspend fun Card.isoAppendRecord(
    shortIdentifier: Long,
    data: ByteArray,
    timeoutMs: Long = 5000,
): ByteArray =
    call {
        isoAppendRecord(
            shortIdentifier,
            data,
            timeoutMs,
        )
    }

/** Suspend iso get challenge; underlying I/O owns its delivery outcome. */
suspend fun Card.isoGetChallenge(
    length: Long,
    timeoutMs: Long = 5000,
): ByteArray =
    call {
        isoGetChallenge(
            length,
            timeoutMs,
        )
    }

/** Suspend iso external authenticate; underlying I/O owns its delivery outcome. */
suspend fun Card.isoExternalAuthenticate(
    number: KeyNumber,
    application: Boolean,
    algorithm: IsoAlgorithm,
    data: ByteArray,
    timeoutMs: Long = 5000,
): ByteArray =
    call {
        isoExternalAuthenticate(
            number,
            application,
            algorithm,
            data,
            timeoutMs,
        )
    }

/** Suspend iso internal authenticate; underlying I/O owns its delivery outcome. */
suspend fun Card.isoInternalAuthenticate(
    number: KeyNumber,
    application: Boolean,
    algorithm: IsoAlgorithm,
    data: ByteArray,
    timeoutMs: Long = 5000,
): ByteArray =
    call {
        isoInternalAuthenticate(
            number,
            application,
            algorithm,
            data,
            timeoutMs,
        )
    }
