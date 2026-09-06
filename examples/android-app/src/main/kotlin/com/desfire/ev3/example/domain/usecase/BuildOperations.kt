package com.desfire.ev3.example.domain.usecase

import com.desfire.ev3.Communication
import com.desfire.ev3.example.domain.model.RawKind
import com.desfire.ev3.example.domain.model.RawPlan
import com.desfire.ev3.example.domain.model.TransactionKind
import com.desfire.ev3.example.domain.model.TransactionReview
import com.desfire.ev3.example.domain.model.hexBytes
import com.desfire.ev3.example.domain.model.sha256Hex
import com.desfire.ev3.example.domain.model.transactionOperation

/** Parse one bounded integer written in decimal or `0x` hexadecimal form. */
internal fun parseNumber(text: String, range: LongRange, label: String): Long {
    val value = text.trim().let { input ->
        if (input.startsWith("0x", ignoreCase = true)) input.drop(2).toLong(16)
        else input.toLong()
    }
    require(value in range) { "$label must be between ${range.first} and ${range.last}." }
    return value
}

/** Build a review object whose typed SDK operation cannot change with later form edits. */
internal fun buildTransactionReview(
    applicationIdText: String,
    kind: TransactionKind,
    fileNumberText: String,
    offsetText: String,
    recordNumberText: String,
    amountText: String,
    dataText: String,
    communication: Communication,
): TransactionReview {
    val applicationId = parseNumber(applicationIdText, 0L..0xFF_FFFFL, "Application ID").toInt()
    val fileNumber = parseNumber(fileNumberText, 0L..31L, "File number").toInt()
    val offset = parseNumber(offsetText, 0L..0xFF_FFFFL, "Offset").toInt()
    val recordNumber = parseNumber(recordNumberText, 0L..0xFF_FFFFL, "Record number").toInt()
    val amount = parseNumber(amountText, 0L..0xFFFF_FFFFL, "Amount")
    val data = dataText.hexBytes(maximumBytes = 64 * 1024)
    return try {
        if (kind == TransactionKind.WRITE_DATA || kind == TransactionKind.WRITE_RECORD ||
            kind == TransactionKind.UPDATE_RECORD
        ) {
            require(data.isNotEmpty()) { "Write operations require at least one data byte." }
        }
        val operation = transactionOperation(
            kind,
            fileNumber,
            offset,
            recordNumber,
            amount,
            data,
            communication,
        )
        val detail = when (kind) {
            TransactionKind.CREDIT -> "Credit $amount to file $fileNumber"
            TransactionKind.DEBIT -> "Debit $amount from file $fileNumber"
            TransactionKind.LIMITED_CREDIT -> "Limited credit $amount to file $fileNumber"
            TransactionKind.WRITE_DATA ->
                "Write ${data.size} byte(s) at offset $offset in file $fileNumber · " +
                    "data SHA-256 ${data.sha256Hex()}"
            TransactionKind.WRITE_RECORD ->
                "Write ${data.size} record byte(s) at offset $offset in file $fileNumber · " +
                    "data SHA-256 ${data.sha256Hex()}"
            TransactionKind.UPDATE_RECORD ->
                "Update record $recordNumber with ${data.size} byte(s) at offset $offset in " +
                    "file $fileNumber · data SHA-256 ${data.sha256Hex()}"
            TransactionKind.CLEAR_RECORD_FILE -> "Clear all records in file $fileNumber"
        }
        val effectiveCommunication = if (kind == TransactionKind.CLEAR_RECORD_FILE) {
            "PLAIN (fixed by command)"
        } else {
            communication.name
        }
        TransactionReview(
            applicationId = applicationId,
            description = "AID %06X · %s · %s".format(
                applicationId,
                detail,
                effectiveCommunication,
            ),
            operation = operation,
        )
    } finally {
        data.fill(0)
    }
}

/** Build one explicit raw request without inferring command layout or continuation policy. */
internal fun buildRawPlan(
    kind: RawKind,
    headerText: String,
    dataText: String,
    maximumResponseText: String,
): RawPlan {
    var header = byteArrayOf()
    var data = byteArrayOf()
    return try {
        header = headerText.hexBytes(allowEmpty = false, maximumBytes = 4)
        data = dataText.hexBytes(maximumBytes = 64 * 1024)
        val maximum = parseNumber(maximumResponseText, 1L..(64L * 1024), "Maximum response")
        when (kind) {
            RawKind.NATIVE -> {
                require(header.size == 1) { "Native header must contain exactly one command byte." }
                RawPlan.Native(
                    command = header[0].toInt() and 0xFF,
                    data = data.copyOf(),
                    maximumResponse = maximum,
                )
            }
            RawKind.ISO_7816 -> {
                require(header.size == 4) { "ISO header must contain CLA, INS, P1, and P2." }
                RawPlan.Iso(
                    cla = header[0].toInt() and 0xFF,
                    ins = header[1].toInt() and 0xFF,
                    p1 = header[2].toInt() and 0xFF,
                    p2 = header[3].toInt() and 0xFF,
                    data = data.copyOf(),
                    maximumResponse = maximum,
                )
            }
        }
    } finally {
        header.fill(0)
        data.fill(0)
    }
}
