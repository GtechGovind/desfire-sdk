package com.desfire.ev3

import java.io.ByteArrayOutputStream

/** Read validated GetDFNames tuples in their documented C ABI encoding. */
public fun BlockingCard.getDfNames(timeoutMs: Long = 5_000): ByteArray =
    invoke(54, longArrayOf(timeoutMs), arrayOf())

/** Erase local managed authentication state without card I/O. */
public fun BlockingCard.resetAuthentication() {
    requireEmpty(invoke(55, longArrayOf(), arrayOf()))
}

/** Stage a MIFARE Classic RestoreTransfer between checked value files. */
public fun BlockingCard.restoreTransfer(
    targetFile: FileNumber,
    sourceFile: FileNumber,
    communication: Communication,
    timeoutMs: Long = 5_000,
) {
    requireEmpty(invoke(56, longArrayOf(targetFile.value.toLong(), sourceFile.value.toLong(),
        communication.value.toLong(), timeoutMs), arrayOf()))
}

/** Create one delegated AES application with exact issuer authorization material. */
public fun BlockingCard.createDelegatedApplication(
    configuration: DelegatedApplication,
    timeoutMs: Long = 5_000,
) {
    requireEmpty(invoke(57, longArrayOf(
        configuration.applicationId.value.toLong(), configuration.keySettings.toLong(),
        configuration.numberOfKeys.toLong(), configuration.slot.toLong(),
        configuration.slotVersion.toLong(), configuration.quotaLimit.toLong(),
        if (configuration.isoFileIdentifiers) 1 else 0,
        configuration.keySettings3?.toLong() ?: -1,
        configuration.isoFileIdentifier?.value?.toLong() ?: -1,
        timeoutMs,
    ), arrayOf(configuration.dfNameBytes, configuration.encryptedDefaultKeyBytes,
        configuration.damMacBytes)))
}

/** Read and decode one delegated-application slot. */
public fun BlockingCard.getDelegatedApplicationInfo(
    slot: Int,
    timeoutMs: Long = 5_000,
): DelegatedApplicationInfo {
    require(slot in 0..0xFFFF)
    return decodeDelegatedApplicationInfo(
        invoke(58, longArrayOf(slot.toLong(), timeoutMs), arrayOf()),
    )
}

/** Decode the fixed JNI representation and reject impossible native field values. */
internal fun decodeDelegatedApplicationInfo(result: ByteArray): DelegatedApplicationInfo {
    requireNativeResultSize(result, 16, "Malformed delegated-application information")
    val slotVersion = readLe32(result, 0)
    val quotaLimit = readLe32(result, 4)
    val freeBlocks = readLe32(result, 8)
    val applicationId = readLe32(result, 12)
    if (slotVersion !in 0..0xFF || quotaLimit !in 0..0xFFFF || freeBlocks !in 0..0xFFFF ||
        applicationId !in 1..0xFFFFFF
    ) {
        result.fill(0)
        throw MalformedNativeResultException("Malformed delegated-application information fields")
    }
    return DelegatedApplicationInfo(
        slotVersion, quotaLimit, freeBlocks, ApplicationId(applicationId),
    )
}

/** Delete one delegated application using its exact issuer-generated DAM MAC. */
public fun BlockingCard.deleteDelegatedApplication(
    applicationId: ApplicationId,
    damMac: ByteArray,
    timeoutMs: Long = 5_000,
) {
    requireEmpty(invoke(59, longArrayOf(applicationId.value.toLong(), timeoutMs), arrayOf(damMac)))
}

/** Read UID data using one explicit documented request variant. */
public fun BlockingCard.getCardUid(
    option: CardUidOption,
    timeoutMs: Long = 5_000,
): ByteArray = invoke(60, longArrayOf(option.code.toLong(), timeoutMs), arrayOf())

/** Set documented PICC option-zero flags. */
public fun BlockingCard.setPiccConfiguration(
    configuration: PiccConfiguration,
    timeoutMs: Long = 5_000,
) {
    requireEmpty(invoke(61, longArrayOf(
        configuration.disableFormat.flag(), configuration.randomIdentifier.flag(),
        configuration.proximityCheckMandatory.flag(),
        configuration.virtualCardAuthenticationMandatory.flag(),
        configuration.errorCodeBinding.flag(), configuration.randomIdentifierConfiguration.flag(),
        configuration.fourByteNuidConfiguration.flag(), timeoutMs,
    ), arrayOf()))
}

/** Set the exact nine-byte option-five capability record. */
public fun BlockingCard.setCapabilityConfiguration(
    capabilities: ByteArray,
    timeoutMs: Long = 5_000,
) {
    require(capabilities.size == 9) { "Capability configuration must contain nine bytes" }
    requireEmpty(invoke(62, longArrayOf(timeoutMs), arrayOf(capabilities)))
}

/** Set a complete two-through-twenty-byte ATS including its length byte. */
public fun BlockingCard.setAts(ats: ByteArray, timeoutMs: Long = 5_000) {
    require(ats.size in 2..20) { "ATS must contain two through twenty bytes" }
    requireEmpty(invoke(63, longArrayOf(timeoutMs), arrayOf(ats)))
}

/** Set the two-byte user ATQA value. */
public fun BlockingCard.setAtqa(atqa: Int, timeoutMs: Long = 5_000) {
    require(atqa in 0..0xFFFF)
    requireEmpty(invoke(64, longArrayOf(atqa.toLong(), timeoutMs), arrayOf()))
}

/** Execute documented ISO UPDATE RECORD instruction 0xDC or 0xDD. */
public fun BlockingCard.isoUpdateRecord(
    instruction: IsoUpdateRecordInstruction,
    record: Int,
    shortIdentifier: Int,
    referenceControl: Int,
    data: ByteArray,
    timeoutMs: Long = 5_000,
): ByteArray {
    require(record in 0..0xFF && shortIdentifier in 0..0x1F && referenceControl in 0..7)
    return invoke(65, longArrayOf(instruction.code.toLong(), record.toLong(),
        shortIdentifier.toLong(), referenceControl.toLong(), timeoutMs), arrayOf(data))
}

/** Execute one through 128 checked mutations and one explicit commit under one card lock. */
public fun BlockingCard.executeTransaction(
    operations: List<TransactionOperation>,
    returnMac: Boolean = false,
    timeoutMs: Long = 5_000,
): ByteArray {
    require(operations.size in 1..128) { "Transaction plan must contain one through 128 operations" }
    val result = invoke(66, longArrayOf(returnMac.flag(), timeoutMs), arrayOf(encode(operations)))
    requireNativeResultSize(
        result,
        if (returnMac) 12 else 0,
        "Malformed native transaction-plan commit result",
    )
    return result
}

/** Suspend-friendly GetDFNames. */
public suspend fun Card.getDfNames(timeoutMs: Long = 5_000): ByteArray =
    call { getDfNames(timeoutMs) }

/** Suspend-friendly local authentication reset. */
public suspend fun Card.resetAuthentication(): Unit = call { resetAuthentication() }

/** Suspend-friendly RestoreTransfer. */
public suspend fun Card.restoreTransfer(targetFile: FileNumber, sourceFile: FileNumber,
    communication: Communication, timeoutMs: Long = 5_000): Unit =
    call { restoreTransfer(targetFile, sourceFile, communication, timeoutMs) }

/** Suspend-friendly delegated application creation. */
public suspend fun Card.createDelegatedApplication(configuration: DelegatedApplication,
    timeoutMs: Long = 5_000): Unit = call { createDelegatedApplication(configuration, timeoutMs) }

/** Suspend-friendly delegated slot query. */
public suspend fun Card.getDelegatedApplicationInfo(slot: Int,
    timeoutMs: Long = 5_000): DelegatedApplicationInfo =
    call { getDelegatedApplicationInfo(slot, timeoutMs) }

/** Suspend-friendly delegated application deletion. */
public suspend fun Card.deleteDelegatedApplication(applicationId: ApplicationId,
    damMac: ByteArray, timeoutMs: Long = 5_000): Unit =
    call { deleteDelegatedApplication(applicationId, damMac, timeoutMs) }

/** Suspend-friendly UID variant query. */
public suspend fun Card.getCardUid(option: CardUidOption,
    timeoutMs: Long = 5_000): ByteArray = call { getCardUid(option, timeoutMs) }

/** Suspend-friendly PICC configuration update. */
public suspend fun Card.setPiccConfiguration(configuration: PiccConfiguration,
    timeoutMs: Long = 5_000): Unit = call { setPiccConfiguration(configuration, timeoutMs) }

/** Suspend-friendly capability configuration update. */
public suspend fun Card.setCapabilityConfiguration(capabilities: ByteArray,
    timeoutMs: Long = 5_000): Unit = call { setCapabilityConfiguration(capabilities, timeoutMs) }

/** Suspend-friendly ATS update. */
public suspend fun Card.setAts(ats: ByteArray, timeoutMs: Long = 5_000): Unit =
    call { setAts(ats, timeoutMs) }

/** Suspend-friendly ATQA update. */
public suspend fun Card.setAtqa(atqa: Int, timeoutMs: Long = 5_000): Unit =
    call { setAtqa(atqa, timeoutMs) }

/** Suspend-friendly ISO UPDATE RECORD. */
public suspend fun Card.isoUpdateRecord(instruction: IsoUpdateRecordInstruction, record: Int,
    shortIdentifier: Int, referenceControl: Int, data: ByteArray,
    timeoutMs: Long = 5_000): ByteArray =
    call { isoUpdateRecord(instruction, record, shortIdentifier, referenceControl, data, timeoutMs) }

/** Suspend-friendly atomic transaction-plan execution. */
public suspend fun Card.executeTransaction(operations: List<TransactionOperation>,
    returnMac: Boolean = false, timeoutMs: Long = 5_000): ByteArray =
    call { executeTransaction(operations, returnMac, timeoutMs) }

/** Encode a transaction plan into the private JNI representation without native pointers. */
private fun encode(operations: List<TransactionOperation>): ByteArray {
    val output = ByteArrayOutputStream()
    output.writeLe32(operations.size)
    for (operation in operations) {
        output.writeLe32(operation.kind)
        output.writeLe32(operation.file.value)
        output.writeLe32(operation.communication.value)
        output.writeLe32(operation.offset.value)
        output.writeLe32(operation.record)
        output.writeLe32(operation.amount.toInt())
        output.writeLe32(operation.dataBytes.size)
        output.write(operation.dataBytes)
    }
    return output.toByteArray()
}

/** Append one uint32 in the private little-endian JNI representation. */
private fun ByteArrayOutputStream.writeLe32(value: Int) {
    write(value); write(value ushr 8); write(value ushr 16); write(value ushr 24)
}

/** Decode one uint32 scalar returned by JNI. */
private fun readLe32(bytes: ByteArray, offset: Int): Int =
    (bytes[offset].toInt() and 0xFF) or ((bytes[offset + 1].toInt() and 0xFF) shl 8) or
        ((bytes[offset + 2].toInt() and 0xFF) shl 16) or
        ((bytes[offset + 3].toInt() and 0xFF) shl 24)

/** Map a Boolean to the C ABI's strict zero-or-one representation. */
private fun Boolean.flag(): Long = if (this) 1 else 0

/** Reject an unexpected mutation payload. */
private fun requireEmpty(bytes: ByteArray) {
    requireEmptyNativeResult(bytes, "Unexpected native mutation payload")
}
