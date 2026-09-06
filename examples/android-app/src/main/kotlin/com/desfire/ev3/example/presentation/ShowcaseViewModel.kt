package com.desfire.ev3.example.presentation

import android.nfc.Tag
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.desfire.ev3.Communication
import com.desfire.ev3.DesfireException
import com.desfire.ev3.example.data.catalog.OperationCatalog
import com.desfire.ev3.example.data.keys.SessionKeyVault
import com.desfire.ev3.example.data.nfc.ConnectionState
import com.desfire.ev3.example.data.nfc.NfcSessionController
import com.desfire.ev3.example.domain.model.ExampleAuthenticationProfile
import com.desfire.ev3.example.domain.model.ExampleKeyMode
import com.desfire.ev3.example.domain.model.FeatureSection
import com.desfire.ev3.example.domain.model.OperationSnapshot
import com.desfire.ev3.example.domain.model.RawKind
import com.desfire.ev3.example.domain.model.RawReview
import com.desfire.ev3.example.domain.model.TransactionKind
import com.desfire.ev3.example.domain.model.hexBytes
import com.desfire.ev3.example.domain.model.sha256Hex
import com.desfire.ev3.example.domain.model.toHex
import com.desfire.ev3.example.domain.model.wipe
import com.desfire.ev3.example.domain.usecase.buildRawPlan
import com.desfire.ev3.example.domain.usecase.buildTransactionReview
import com.desfire.ev3.example.domain.usecase.parseNumber
import com.desfire.ev3.offline.calculateTransactionMacAes
import com.desfire.ev3.offline.deriveNxpAes128
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Lifecycle owner for all showcase state, SDK actions, and session-only secrets. */
internal class ShowcaseViewModel : ViewModel() {
    private val keys = SessionKeyVault()
    private val offlineBusy = AtomicBoolean(false)
    private val offlineEpoch = AtomicLong(0)
    private val mutableState = MutableStateFlow(ShowcaseState())
    val state: StateFlow<ShowcaseState> = mutableState.asStateFlow()

    private val controller = NfcSessionController(
        report = ::publish,
        connectionChanged = ::updateConnection,
    )

    init {
        try {
            val operations = OperationCatalog.load()
            mutableState.update { it.copy(catalog = operations, catalogMatches = operations) }
        } catch (failure: Throwable) {
            publish(localFailure("Operation catalog", failure.message ?: "Catalog could not be loaded."))
        }
    }

    /** Select one of the six stable feature screens. */
    fun selectSection(section: FeatureSection) {
        mutableState.update { it.copy(section = section) }
    }

    /** Update Android NFC capability shown by the connection banner. */
    fun updateNfcState(available: Boolean, enabled: Boolean) {
        mutableState.update { it.copy(nfcAvailable = available, nfcEnabled = enabled) }
    }

    /** Admit one Android Tag into the data-layer session owner. */
    fun acceptTag(tag: Tag) = controller.accept(tag)

    /** Close card ownership and wipe keys whenever the host leaves the foreground. */
    fun onHostPaused() {
        offlineEpoch.incrementAndGet()
        controller.disconnect("Screen left the foreground; session keys were cleared.")
        keys.clear()
        mutableState.value.rawReview?.plan?.wipe()
        mutableState.update {
            it.copy(
                keySource = "NONE",
                transactionReview = null,
                rawReview = null,
                inputClearEpoch = it.inputClearEpoch + 1,
            )
        }
    }

    /** Close the current card and wipe all session-scoped key material. */
    fun disconnect() {
        offlineEpoch.incrementAndGet()
        controller.disconnect()
        keys.clear()
        mutableState.value.rawReview?.plan?.wipe()
        mutableState.update {
            it.copy(
                keySource = "NONE",
                transactionReview = null,
                rawReview = null,
                inputClearEpoch = it.inputClearEpoch + 1,
            )
        }
    }

    /** Run read-only discovery operations. */
    fun readVersion() = controller.readVersion()

    /** Read and display all native application identifiers reported by the card. */
    fun readApplications() = controller.readApplications()

    /** Read the card's currently reported free-memory value. */
    fun readFreeMemory() = controller.readFreeMemory()

    /** Select one native application after strict range parsing. */
    fun selectApplication(applicationId: String) = validated("SelectApplication") {
        controller.selectApplication(
            parseNumber(applicationId, 0L..0xFF_FFFFL, "Application ID").toInt(),
        )
    }

    /** Replace session key material and immediately report only its source family. */
    fun loadKey(
        mode: ExampleKeyMode,
        secretHex: String,
        diversificationHex: String,
        referenceHex: String,
    ) = validated("Load session key") {
        offlineEpoch.incrementAndGet()
        controller.invalidateForKeyChange()
        keys.clear()
        mutableState.update {
            it.copy(keySource = "NONE", inputClearEpoch = it.inputClearEpoch + 1)
        }
        var secret = byteArrayOf()
        var diversification = byteArrayOf()
        var reference = byteArrayOf()
        try {
            secret = secretHex.hexBytes(allowEmpty = false, maximumBytes = 16)
            diversification = diversificationHex.hexBytes(maximumBytes = 31)
            reference = referenceHex.hexBytes(maximumBytes = 1_024)
            try {
                keys.configure(mode, secret, diversification, reference)
            } catch (failure: Throwable) {
                mutableState.update {
                    it.copy(keySource = "NONE", inputClearEpoch = it.inputClearEpoch + 1)
                }
                throw failure
            }
        } finally {
            secret.fill(0)
            diversification.fill(0)
            reference.fill(0)
        }
        mutableState.update { it.copy(keySource = keys.description()) }
        publish(
            OperationSnapshot(
                title = "Session key loaded",
                detail = "${keys.description()} key source loaded. Secret value is redacted.",
                outcome = "SUCCEEDED",
                recovery = "Key will be wiped on clear, disconnect, or pause.",
            ),
        )
    }

    /** Clear all vault-owned copies without card I/O. */
    fun clearKey() {
        offlineEpoch.incrementAndGet()
        controller.invalidateForKeyChange()
        keys.clear()
        mutableState.update {
            it.copy(keySource = "NONE", inputClearEpoch = it.inputClearEpoch + 1)
        }
        publish(OperationSnapshot("Session key cleared", "Vault-owned key arrays were overwritten."))
    }

    /** Establish one explicit authentication profile with no default key. */
    fun authenticate(
        profile: ExampleAuthenticationProfile,
        keyNumberText: String,
        applicationIdText: String,
    ) = validated("Authenticate") {
        val keyNumber = parseNumber(keyNumberText, 0L..63L, "Key number").toInt()
        val application = applicationIdText.trim().takeIf { it.isNotEmpty() }?.let {
            parseNumber(it, 0L..0xFF_FFFFL, "Application ID").toInt()
        }
        val generation = keys.generationToken()
        controller.authenticate(profile, keyNumber, application) { selectedApplication ->
            keys.source(
                applicationId = selectedApplication,
                expectedGeneration = generation,
            )
        }
    }

    /** Run one typed file action using the active selected application. */
    fun readFileIds() = controller.readFileIds()

    /** Parse a file number and read its typed settings bytes. */
    fun readFileSettings(fileNumberText: String) = validated("GetFileSettings") {
        controller.readFileSettings(parseNumber(fileNumberText, 0L..31L, "File number").toInt())
    }

    /** Parse bounded read inputs and execute one typed file read. */
    fun readFile(
        fileNumberText: String,
        offsetText: String,
        lengthText: String,
        communication: Communication,
    ) = validated("ReadData") {
        controller.readFile(
            parseNumber(fileNumberText, 0L..31L, "File number").toInt(),
            parseNumber(offsetText, 0L..0xFF_FFFFL, "Offset").toInt(),
            parseNumber(lengthText, 0L..(64L * 1024), "Length"),
            communication,
        )
    }

    /** Freeze typed transaction input for a separate explicit confirmation. */
    fun reviewTransaction(
        applicationId: String,
        kind: TransactionKind,
        fileNumber: String,
        offset: String,
        recordNumber: String,
        amount: String,
        data: String,
        communication: Communication,
    ) = validated("Review transaction") {
        val review = buildTransactionReview(
            applicationId,
            kind,
            fileNumber,
            offset,
            recordNumber,
            amount,
            data,
            communication,
        )
        mutableState.update { it.copy(transactionReview = review) }
        publish(
            OperationSnapshot(
                title = "Transaction review required",
                detail = review.description,
                recovery = "Verify the fixed review, then use Confirm and send exactly once.",
            ),
        )
    }

    /** Dispatch the immutable reviewed transaction once and remove the confirmation token. */
    fun confirmTransaction() {
        val review = mutableState.value.transactionReview ?: run {
            publish(localFailure("ExecuteTransaction", "Create a transaction review first."))
            return
        }
        mutableState.update { it.copy(transactionReview = null) }
        controller.executeReviewedTransaction(review.applicationId, review.operation)
    }

    /** Remove a pending review without card I/O. */
    fun cancelTransactionReview() {
        mutableState.update { it.copy(transactionReview = null) }
        publish(OperationSnapshot("Transaction review cancelled", "No mutation was sent."))
    }

    /** Freeze one raw request for a separate explicit expert confirmation. */
    fun reviewRaw(kind: RawKind, header: String, data: String, maximumResponse: String) =
        validated("Arm raw request") {
            val plan = buildRawPlan(kind, header, data, maximumResponse)
            val review = RawReview(
                description = "$kind · header ${plan.headerIdentity()} · " +
                    "${plan.dataSize()} data byte(s) · data SHA-256 ${plan.dataDigest()} · " +
                    "maximum ${plan.maximumResponse()} byte(s)",
                plan = plan,
            )
            mutableState.value.rawReview?.plan?.wipe()
            mutableState.update { it.copy(rawReview = review) }
            publish(
                OperationSnapshot(
                    title = "Raw request review required",
                    detail = review.description,
                    recovery = "Verify the exact request, then confirm once and present the card.",
                ),
            )
        }

    /** Close managed ownership and arm the immutable raw review for one fresh discovery. */
    fun confirmRaw() {
        val review = mutableState.value.rawReview ?: run {
            publish(localFailure("Raw exchange", "Create a raw request review first."))
            return
        }
        mutableState.update { it.copy(rawReview = null) }
        controller.armRaw(review.plan)
    }

    /** Remove an unconfirmed raw request without touching card state. */
    fun cancelRawReview() {
        val review = mutableState.value.rawReview
        mutableState.update { it.copy(rawReview = null) }
        review?.plan?.wipe()
        publish(OperationSnapshot("Raw review cancelled", "No raw request was sent."))
    }

    /** Derive an AES-128 key offline and keep it redacted in the session vault. */
    fun deriveOffline(diversificationHex: String) = offline("Offline AES derivation") {
        var diversification = byteArrayOf()
        var lease: com.desfire.ev3.example.data.keys.SecretLease? = null
        try {
            diversification = diversificationHex.hexBytes(allowEmpty = false, maximumBytes = 31)
            lease = keys.offlineLease()
            val activeLease = lease
            val derived = when (activeLease.mode) {
                ExampleKeyMode.DIRECT,
                ExampleKeyMode.DERIVED,
                -> deriveNxpAes128(activeLease.secret, diversification)
                ExampleKeyMode.PROVIDER -> {
                    val source = keys.source(
                        diversificationOverride = diversification,
                        expectedGeneration = activeLease.generation,
                    )
                    deriveNxpAes128(source as com.desfire.ev3.KeySource.Provider)
                }
                ExampleKeyMode.GKEY_PROVIDER -> error(
                    "GKey already defines UID binding and cannot be used as an NXP master-key source.",
                )
            }
            try {
                check(keys.replaceWithDirectIfGeneration(activeLease.generation, derived)) {
                    "The session key changed while derivation was running."
                }
                mutableState.update { it.copy(keySource = keys.description()) }
                "Derived 16-byte key stored as a redacted DIRECT session source."
            } finally {
                derived.fill(0)
            }
        } finally {
            lease?.close()
            diversification.fill(0)
        }
    }

    /** Calculate a transaction MAC from caller-supplied authoritative TMI. */
    fun calculateTransactionMac(counterText: String, uidHex: String, tmiHex: String) =
        offline("Offline transaction MAC") {
            val counter = parseNumber(counterText, 0L..0xFFFF_FFFFL, "Transaction counter")
            var uid = byteArrayOf()
            var tmi = byteArrayOf()
            var lease: com.desfire.ev3.example.data.keys.SecretLease? = null
            try {
                uid = uidHex.hexBytes(allowEmpty = false, maximumBytes = 32)
                tmi = tmiHex.hexBytes(allowEmpty = false, maximumBytes = 64 * 1024)
                lease = keys.offlineLease()
                val activeLease = lease
                val mac = when (activeLease.mode) {
                    ExampleKeyMode.DIRECT -> calculateTransactionMacAes(
                        activeLease.secret,
                        counter,
                        uid,
                        tmi,
                    )
                    ExampleKeyMode.DERIVED -> {
                        val derived = deriveNxpAes128(
                            activeLease.secret,
                            activeLease.diversification,
                        )
                        try {
                            calculateTransactionMacAes(derived, counter, uid, tmi)
                        } finally {
                            derived.fill(0)
                        }
                    }
                    ExampleKeyMode.PROVIDER -> calculateTransactionMacAes(
                        keys.source(
                            expectedGeneration = activeLease.generation,
                        ) as com.desfire.ev3.KeySource.Provider,
                        transactionCounter = counter,
                        uid = uid,
                        transactionInput = tmi,
                    )
                    ExampleKeyMode.GKEY_PROVIDER -> calculateTransactionMacAes(
                        keys.source(
                            diversificationOverride = uid,
                            expectedGeneration = activeLease.generation,
                        ) as com.desfire.ev3.KeySource.Provider,
                        transactionCounter = counter,
                        uid = uid,
                        transactionInput = tmi,
                    )
                }
                try {
                    "MAC ${mac.toHex()}"
                } finally {
                    mac.fill(0)
                }
            } finally {
                lease?.close()
                uid.fill(0)
                tmi.fill(0)
            }
        }

    /** Search all 120 stable manifest entries without changing the selected screen. */
    fun searchCatalog(query: String) {
        mutableState.update {
            it.copy(
                catalogQuery = query,
                catalogMatches = OperationCatalog.search(it.catalog, query),
            )
        }
    }

    /** Run one local/offline action on a worker and publish its result safely. */
    private fun offline(title: String, operation: () -> String) {
        if (!offlineBusy.compareAndSet(false, true)) {
            publish(localFailure(title, "Another offline operation is running."))
            return
        }
        val admittedEpoch = offlineEpoch.get()
        viewModelScope.launch {
            try {
                val detail = withContext(Dispatchers.Default) { operation() }
                if (offlineEpoch.get() != admittedEpoch) return@launch
                publish(
                    OperationSnapshot(
                        title = title,
                        detail = detail,
                        outcome = "SUCCEEDED",
                        cardStatus = "No card I/O",
                    ),
                )
            } catch (failure: DesfireException) {
                if (offlineEpoch.get() == admittedEpoch) {
                    publish(
                        OperationSnapshot(
                            title = title,
                            detail = failure.message ?: "Offline SDK operation failed.",
                            errorCode = failure.errorCode?.name
                                ?: "UNKNOWN_VALUE(${failure.code})",
                            outcome = failure.deliveryOutcome?.name
                                ?: "UNKNOWN_VALUE(${failure.outcome})",
                            cardStatus = "No card I/O",
                            recovery = "No card command was sent; correct the input and retry locally.",
                        ),
                    )
                }
            } catch (failure: Throwable) {
                if (offlineEpoch.get() == admittedEpoch) {
                    publish(localFailure(title, failure.message ?: "Offline operation failed."))
                }
            } finally {
                offlineBusy.set(false)
            }
        }
    }

    /** Convert invalid form input into NOT_SENT evidence. */
    private inline fun validated(title: String, operation: () -> Unit) {
        try {
            operation()
        } catch (failure: Throwable) {
            publish(localFailure(title, failure.message ?: "Invalid input."))
        }
    }

    /** Replace the visible operation evidence atomically. */
    private fun publish(snapshot: OperationSnapshot) {
        mutableState.update {
            val historyEntry = snapshot.copy(detail = "Details retained only in the latest result.")
            it.copy(snapshot = snapshot, history = (listOf(historyEntry) + it.history).take(12))
        }
    }

    /** Apply data-layer connection ownership without disturbing operation evidence. */
    private fun updateConnection(connection: ConnectionState) {
        mutableState.update {
            it.copy(
                connected = connection.connected,
                selectedApplication = connection.selectedApplication,
                unknownLocked = connection.unknownLocked,
            )
        }
    }

    /** Build local-validation evidence that guarantees zero card I/O for this action. */
    private fun localFailure(title: String, detail: String): OperationSnapshot = OperationSnapshot(
        title = title,
        detail = detail,
        errorCode = "LOCAL_VALIDATION",
        outcome = "NOT_SENT",
    )

    /** Wipe session material and close transport ownership. */
    override fun onCleared() {
        offlineEpoch.incrementAndGet()
        mutableState.value.rawReview?.plan?.wipe()
        keys.clear()
        controller.shutdown()
        super.onCleared()
    }
}

/** Return command-data size without exposing or copying the retained bytes. */
private fun com.desfire.ev3.example.domain.model.RawPlan.dataSize(): Int = when (this) {
    is com.desfire.ev3.example.domain.model.RawPlan.Native -> data.size
    is com.desfire.ev3.example.domain.model.RawPlan.Iso -> data.size
}

/** Return the exact normalized command header retained by one raw review. */
private fun com.desfire.ev3.example.domain.model.RawPlan.headerIdentity(): String = when (this) {
    is com.desfire.ev3.example.domain.model.RawPlan.Native -> "%02X".format(command)
    is com.desfire.ev3.example.domain.model.RawPlan.Iso -> "%02X%02X%02X%02X".format(
        cla,
        ins,
        p1,
        p2,
    )
}

/** Return a stable identity for the exact retained command-data bytes. */
private fun com.desfire.ev3.example.domain.model.RawPlan.dataDigest(): String = when (this) {
    is com.desfire.ev3.example.domain.model.RawPlan.Native -> data.sha256Hex()
    is com.desfire.ev3.example.domain.model.RawPlan.Iso -> data.sha256Hex()
}

/** Return the parsed response bound retained by one raw review. */
private fun com.desfire.ev3.example.domain.model.RawPlan.maximumResponse(): Long = when (this) {
    is com.desfire.ev3.example.domain.model.RawPlan.Native -> maximumResponse
    is com.desfire.ev3.example.domain.model.RawPlan.Iso -> maximumResponse
}
