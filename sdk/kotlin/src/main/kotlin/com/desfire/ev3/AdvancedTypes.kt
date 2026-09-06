package com.desfire.ev3

/** Documented GetCardUID request variant. */
public enum class CardUidOption(internal val code: Int) {
    OMITTED(0),
    WITHOUT_NUID(1),
    WITH_NUID(2),
}

/** Named PICC SetConfiguration option-zero flags. */
public data class PiccConfiguration(
    public val disableFormat: Boolean = false,
    public val randomIdentifier: Boolean = false,
    public val proximityCheckMandatory: Boolean = false,
    public val virtualCardAuthenticationMandatory: Boolean = false,
    public val errorCodeBinding: Boolean = false,
    public val randomIdentifierConfiguration: Boolean = false,
    public val fourByteNuidConfiguration: Boolean = false,
)

/** Checked delegated AES application configuration and issuer authorization material. */
public class DelegatedApplication(
    public val applicationId: ApplicationId,
    public val keySettings: Int,
    public val numberOfKeys: Int,
    public val slot: Int,
    public val slotVersion: Int,
    public val quotaLimit: Int,
    public val isoFileIdentifiers: Boolean,
    public val keySettings3: Int? = null,
    public val isoFileIdentifier: IsoFileIdentifier? = null,
    public val keySets: DelegatedKeySets? = null,
    dfName: ByteArray = byteArrayOf(),
    encryptedDefaultKey: ByteArray,
    damMac: ByteArray,
) {
    internal val dfNameBytes = dfName.copyOf()
    internal val encryptedDefaultKeyBytes = encryptedDefaultKey.copyOf()
    internal val damMacBytes = damMac.copyOf()

    init {
        require(applicationId.value != 0) { "A delegated application ID must be nonzero" }
        require(keySettings in 0..0xFF && numberOfKeys in 0..0xFF)
        require(slot in 0..0xFFFF && slotVersion in 0..0xFF && quotaLimit in 0..0xFFFF)
        require(keySettings3 == null || keySettings3 in 0..0xFF)
        require(dfNameBytes.size <= 16) { "A delegated DF name cannot exceed sixteen bytes" }
        require(encryptedDefaultKeyBytes.size == 32) {
            "A delegated encrypted default key must contain 32 bytes"
        }
        require(damMacBytes.size == 8) { "A delegated application MAC must contain eight bytes" }
    }
}

/** Optional delegated-application key-set fields covered by the issuer MAC. */
public data class DelegatedKeySets(
    public val activeVersion: Int,
    public val count: Int,
    public val maximumKeySize: Int,
    public val settings: Int,
) {
    init {
        require(activeVersion in 0..0xFF && count in 0..0xFF && maximumKeySize in 0..0xFF &&
            settings in 0..0xFF) { "Delegated key-set fields must fit one byte" }
    }
}

/** Decoded delegated-application slot state. */
public data class DelegatedApplicationInfo(
    public val slotVersion: Int,
    public val quotaLimit: Int,
    public val freeBlocks: Int,
    public val applicationId: ApplicationId,
)

/** Documented ISO UPDATE RECORD instruction variant. */
public enum class IsoUpdateRecordInstruction(internal val code: Int) {
    UPDATE(0xDC),
    UPDATE_OR_APPEND(0xDD),
}

/** One checked mutation in an atomic managed transaction plan. */
public sealed class TransactionOperation private constructor(
    internal val kind: Int,
    public val file: FileNumber,
    public val communication: Communication,
    public val offset: ByteOffset,
    public val record: Int,
    public val amount: Long,
    data: ByteArray,
) {
    internal val dataBytes = data.copyOf()

    /** Write bytes to a standard or backup data file. */
    public class WriteData(
        file: FileNumber,
        offset: ByteOffset,
        data: ByteArray,
        communication: Communication,
    ) : TransactionOperation(1, file, communication, offset, 0, 0, data)

    /** Stage value-file credit. */
    public class Credit(file: FileNumber, amount: Long, communication: Communication) :
        TransactionOperation(2, file, communication, ByteOffset(0), 0, amount, byteArrayOf())

    /** Stage value-file debit. */
    public class Debit(file: FileNumber, amount: Long, communication: Communication) :
        TransactionOperation(3, file, communication, ByteOffset(0), 0, amount, byteArrayOf())

    /** Stage value-file limited credit. */
    public class LimitedCredit(file: FileNumber, amount: Long, communication: Communication) :
        TransactionOperation(4, file, communication, ByteOffset(0), 0, amount, byteArrayOf())

    /** Write bytes to a record file. */
    public class WriteRecord(
        file: FileNumber,
        offset: ByteOffset,
        data: ByteArray,
        communication: Communication,
    ) : TransactionOperation(5, file, communication, offset, 0, 0, data)

    /** Replace bytes within one record. */
    public class UpdateRecord(
        file: FileNumber,
        public val recordNumber: Int,
        offset: ByteOffset,
        data: ByteArray,
        communication: Communication,
    ) : TransactionOperation(6, file, communication, offset, recordNumber, 0, data) {
        init { require(recordNumber in 0..0xFFFFFF) }
    }

    /** Stage removal of every record in a record file. */
    public class ClearRecordFile(file: FileNumber) :
        TransactionOperation(7, file, Communication.PLAIN, ByteOffset(0), 0, 0, byteArrayOf())

    init {
        require(amount in 0..0xFFFF_FFFFL) { "Transaction amount must fit uint32" }
    }
}
