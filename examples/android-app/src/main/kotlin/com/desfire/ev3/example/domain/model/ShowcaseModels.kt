package com.desfire.ev3.example.domain.model

import com.desfire.ev3.Communication
import com.desfire.ev3.Framing
import com.desfire.ev3.TransactionOperation
import java.security.MessageDigest

/** Six stable feature areas presented by the showcase. */
internal enum class FeatureSection(val title: String, val summary: String) {
    DISCOVER("Discover", "Card identity, applications, memory, and selection"),
    AUTHENTICATE("Authenticate", "Standard AES, EV2 First, EV2 NonFirst, and ISO AES"),
    FILES("Files", "Typed file discovery, settings, and bounded reads"),
    TRANSACTIONS("Transactions", "Reviewed atomic mutations with delivery evidence"),
    RAW("Raw", "Explicit ISO-wrapped native and true ISO exchanges"),
    OFFLINE("Offline", "AES derivation and authoritative transaction-MAC input"),
}

/** One immutable UI record for an SDK operation or lifecycle transition. */
internal data class OperationSnapshot(
    val title: String,
    val detail: String,
    val errorCode: String = "—",
    val outcome: String = "NOT_SENT",
    val cardStatus: String = "—",
    val requiresReconciliation: Boolean = false,
    val recovery: String = "No follow-up action is required.",
) {
    /** Format stable delivery evidence without request payloads or key material. */
    fun evidence(): String = buildString {
        appendLine("Error code  $errorCode")
        appendLine("Outcome     $outcome")
        appendLine("Card status $cardStatus")
        appendLine("Reconcile  ${if (requiresReconciliation) "Required" else "Not required"}")
        append(recovery)
    }
}

/** Searchable summary sourced from the canonical 120-operation binding manifest. */
internal data class CatalogOperation(
    val id: Int,
    val name: String,
    val domain: String,
    val summary: String,
    val mutation: Boolean,
    val surface: String,
    val authentication: String,
    val sessionEffect: String,
    val prerequisites: String,
    val recovery: String,
)

/** Marks locally malformed card data after a command has already completed successfully. */
internal class MalformedCardDataException(message: String) : IllegalStateException(message)

/**
 * Raw request descriptor armed before a separate, exclusively owned ISO-DEP discovery.
 *
 * The descriptor retains one app-owned command-data copy so cancellation and completion can wipe
 * it. The SDK request object is deliberately created only at dispatch time.
 */
internal sealed interface RawPlan {
    /** One ISO-wrapped native logical exchange. */
    class Native(
        val command: Int,
        val data: ByteArray,
        val maximumResponse: Long,
    ) : RawPlan

    /** One true ISO/IEC 7816 APDU exchange. */
    class Iso(
        val cla: Int,
        val ins: Int,
        val p1: Int,
        val p2: Int,
        val data: ByteArray,
        val maximumResponse: Long,
    ) : RawPlan
}

/** Overwrite the app-owned command-data copy after cancellation or dispatch. */
internal fun RawPlan.wipe() {
    when (this) {
        is RawPlan.Native -> data.fill(0)
        is RawPlan.Iso -> data.fill(0)
    }
}

/** Reviewed transaction object retained between review and explicit confirmation. */
internal data class TransactionReview(
    val applicationId: Int,
    val description: String,
    val operation: TransactionOperation,
)

/** Raw plan and human-readable fixed review retained before explicit dispatch confirmation. */
internal data class RawReview(val description: String, val plan: RawPlan)

/** Input family used to construct a reviewed transaction operation. */
internal enum class TransactionKind {
    CREDIT,
    DEBIT,
    LIMITED_CREDIT,
    WRITE_DATA,
    WRITE_RECORD,
    UPDATE_RECORD,
    CLEAR_RECORD_FILE,
}

/** User-selected key source with no implicit or test default. */
internal enum class ExampleKeyMode {
    DIRECT,
    DERIVED,
    PROVIDER,
    GKEY_PROVIDER,
}

/** User-selected managed authentication profile. */
internal enum class ExampleAuthenticationProfile {
    STANDARD_AES,
    EV2_FIRST,
    EV2_NON_FIRST,
    ISO_AES,
}

/** User-selected raw command family. */
internal enum class RawKind {
    NATIVE,
    ISO_7816,
}

/** Build a checked transaction operation from a review-safe input object. */
internal fun transactionOperation(
    kind: TransactionKind,
    fileNumber: Int,
    offset: Int,
    recordNumber: Int,
    amount: Long,
    data: ByteArray,
    communication: Communication,
): TransactionOperation = when (kind) {
    TransactionKind.CREDIT -> TransactionOperation.Credit(
        com.desfire.ev3.FileNumber(fileNumber),
        amount,
        communication,
    )
    TransactionKind.DEBIT -> TransactionOperation.Debit(
        com.desfire.ev3.FileNumber(fileNumber),
        amount,
        communication,
    )
    TransactionKind.LIMITED_CREDIT -> TransactionOperation.LimitedCredit(
        com.desfire.ev3.FileNumber(fileNumber),
        amount,
        communication,
    )
    TransactionKind.WRITE_DATA -> TransactionOperation.WriteData(
        com.desfire.ev3.FileNumber(fileNumber),
        com.desfire.ev3.ByteOffset(offset),
        data,
        communication,
    )
    TransactionKind.WRITE_RECORD -> TransactionOperation.WriteRecord(
        com.desfire.ev3.FileNumber(fileNumber),
        com.desfire.ev3.ByteOffset(offset),
        data,
        communication,
    )
    TransactionKind.UPDATE_RECORD -> TransactionOperation.UpdateRecord(
        com.desfire.ev3.FileNumber(fileNumber),
        recordNumber,
        com.desfire.ev3.ByteOffset(offset),
        data,
        communication,
    )
    TransactionKind.CLEAR_RECORD_FILE -> TransactionOperation.ClearRecordFile(
        com.desfire.ev3.FileNumber(fileNumber),
    )
}

/** Strict representation of the 28-byte native GetVersion response. */
internal data class VersionReport(
    val hardware: VersionPart,
    val software: VersionPart,
    val uid: ByteArray,
    val batch: ByteArray,
    val productionWeek: Int,
    val productionYear: Int,
    val raw: ByteArray,
) {
    companion object {
        /** Parse all fixed fields or reject the response without displaying partial data. */
        fun parse(payload: ByteArray): VersionReport {
            if (payload.size != 28) {
                throw MalformedCardDataException("GetVersion must return exactly 28 bytes.")
            }
            return VersionReport(
                hardware = VersionPart.parse(payload, 0),
                software = VersionPart.parse(payload, 7),
                uid = payload.copyOfRange(14, 21),
                batch = payload.copyOfRange(21, 26),
                productionWeek = payload[26].toUnsignedInt(),
                productionYear = payload[27].toUnsignedInt(),
                raw = payload.copyOf(),
            )
        }
    }

    /** Format card-provided identifiers locally without logging them. */
    fun display(): String = buildString {
        appendLine("Hardware  ${hardware.display()}")
        appendLine("Software  ${software.display()}")
        appendLine("UID       ${uid.toHex()}")
        appendLine("Batch     ${batch.toHex()}")
        appendLine("Produced  week ${productionWeek.toBcdLabel()}, year ${productionYear.toBcdLabel()}")
        append("Raw       ${raw.toHex()}")
    }
}

/** One unmodified seven-byte card version descriptor. */
internal data class VersionPart(
    val vendor: Int,
    val type: Int,
    val subtype: Int,
    val major: Int,
    val minor: Int,
    val storage: Int,
    val protocol: Int,
) {
    companion object {
        /** Parse one descriptor from an already length-checked GetVersion payload. */
        fun parse(payload: ByteArray, offset: Int): VersionPart = VersionPart(
            vendor = payload[offset].toUnsignedInt(),
            type = payload[offset + 1].toUnsignedInt(),
            subtype = payload[offset + 2].toUnsignedInt(),
            major = payload[offset + 3].toUnsignedInt(),
            minor = payload[offset + 4].toUnsignedInt(),
            storage = payload[offset + 5].toUnsignedInt(),
            protocol = payload[offset + 6].toUnsignedInt(),
        )
    }

    /** Format fields without inferring undocumented product or storage semantics. */
    fun display(): String =
        "vendor=${vendor.hexByte()} type=${type.hexByte()} subtype=${subtype.hexByte()} " +
            "version=$major.$minor storage=${storage.hexByte()} protocol=${protocol.hexByte()}"
}

/** Convert an unsigned wire byte to its non-negative integer representation. */
internal fun Byte.toUnsignedInt(): Int = toInt() and 0xFF

/** Format one byte-sized value as uppercase hexadecimal. */
internal fun Int.hexByte(): String = "0x%02X".format(this)

/** Format a byte sequence with no separators. */
internal fun ByteArray.toHex(): String =
    joinToString(separator = "") { "%02X".format(it.toUnsignedInt()) }

/** Return an uppercase SHA-256 identity while clearing the temporary digest array. */
internal fun ByteArray.sha256Hex(): String {
    val digest = MessageDigest.getInstance("SHA-256").digest(this)
    return try {
        digest.toHex()
    } finally {
        digest.fill(0)
    }
}

/** Bound UI formatting while retaining full response size and a stable response identity. */
internal fun ByteArray.toBoundedDisplay(maximumPreviewBytes: Int = 256): String {
    require(maximumPreviewBytes > 0) { "Preview bound must be positive." }
    val preview = copyOfRange(0, minOf(size, maximumPreviewBytes))
    return try {
        buildString {
            appendLine("$size byte(s)")
            append("Data      ${preview.toHex()}")
            if (size > preview.size) append("… (${size - preview.size} byte(s) omitted)")
            appendLine()
            append("SHA-256   ${sha256Hex()}")
        }
    } finally {
        preview.fill(0)
    }
}

/** Decode valid packed BCD while preserving invalid wire values as hexadecimal. */
private fun Int.toBcdLabel(): String {
    val high = this ushr 4
    val low = this and 0x0F
    return if (high <= 9 && low <= 9) "${high * 10 + low} (${hexByte()})" else hexByte()
}

/** The Android transport always presents native commands through ISO-wrapped framing. */
internal val androidNativeFraming: Framing = Framing.ISO_WRAPPED
