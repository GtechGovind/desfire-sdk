package com.desfire.ev3.example.data.nfc

import android.nfc.Tag
import android.nfc.tech.IsoDep
import com.desfire.ev3.ApplicationId
import com.desfire.ev3.AuthenticationInfo
import com.desfire.ev3.Card
import com.desfire.ev3.Communication
import com.desfire.ev3.DesfireException
import com.desfire.ev3.ErrorCode
import com.desfire.ev3.FileNumber
import com.desfire.ev3.KeyNumber
import com.desfire.ev3.KeySource
import com.desfire.ev3.MalformedNativeResultException
import com.desfire.ev3.Outcome
import com.desfire.ev3.TransactionOperation
import com.desfire.ev3.android.AndroidCardSession
import com.desfire.ev3.android.AndroidRawSession
import com.desfire.ev3.applicationIds
import com.desfire.ev3.authenticateEv2FirstAes
import com.desfire.ev3.authenticateEv2NonFirstAes
import com.desfire.ev3.authenticateIsoAes
import com.desfire.ev3.authenticateStandardAes
import com.desfire.ev3.example.domain.model.ExampleAuthenticationProfile
import com.desfire.ev3.example.domain.model.MalformedCardDataException
import com.desfire.ev3.example.domain.model.OperationSnapshot
import com.desfire.ev3.example.domain.model.RawPlan
import com.desfire.ev3.example.domain.model.VersionReport
import com.desfire.ev3.example.domain.model.androidNativeFraming
import com.desfire.ev3.example.domain.model.toBoundedDisplay
import com.desfire.ev3.example.domain.model.toHex
import com.desfire.ev3.example.domain.model.wipe
import com.desfire.ev3.executeTransaction
import com.desfire.ev3.fileIds
import com.desfire.ev3.freeMemory
import com.desfire.ev3.getFileSettings
import com.desfire.ev3.getVersion
import com.desfire.ev3.readData
import com.desfire.ev3.selectApplication
import com.desfire.ev3.raw.isoExchange
import com.desfire.ev3.raw.nativeExchange
import com.desfire.ev3.raw.IsoApdu
import com.desfire.ev3.raw.NativeRequest
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/** Current managed reader state exposed to the presentation layer without transport ownership. */
internal data class ConnectionState(
    val connected: Boolean = false,
    val selectedApplication: Int? = null,
    val unknownLocked: Boolean = false,
)

/**
 * Owns Android ISO-DEP, managed/raw SDK sessions, serialization, and delivery-state recovery.
 *
 * Managed and raw channels are never open together. An UNKNOWN outcome closes the active channel
 * and locks command admission until Android reports a newly discovered tag.
 */
internal class NfcSessionController(
    private val report: (OperationSnapshot) -> Unit,
    private val connectionChanged: (ConnectionState) -> Unit,
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val operationGate = Mutex()
    private val closing = AtomicBoolean(false)
    private val disconnectRequested = AtomicBoolean(false)
    private val activeSession = AtomicReference<AndroidCardSession?>(null)
    private val activeRawSession = AtomicReference<AndroidRawSession?>(null)
    private val openingIsoDep = AtomicReference<IsoDep?>(null)
    private val pendingRaw = AtomicReference<RawPlan?>(null)
    private var selectedApplication: Int? = null
    private var unknownLocked = false

    /** Connect a newly discovered ISO-DEP tag as managed, or execute one armed raw request. */
    fun accept(tag: Tag) {
        if (closing.get()) {
            report(localFailure("Connect", "This reader owner has already been shut down."))
            return
        }
        disconnectRequested.set(false)
        requestActiveCancellation()
        scope.launch {
            operationGate.withLock {
                val plan = pendingRaw.getAndSet(null)
                if (plan != null) {
                    executeRaw(tag, plan)
                } else {
                    openManaged(tag)
                }
            }
        }
    }

    /** Request cancellation immediately and close the managed session in queue order. */
    fun disconnect(reason: String = "Reader session closed.") {
        disconnectRequested.set(true)
        pendingRaw.getAndSet(null)?.wipe()
        requestActiveCancellation()
        scope.launch {
            operationGate.withLock {
                try {
                    closeAll()
                    report(OperationSnapshot("Disconnected", reason))
                } catch (failure: Throwable) {
                    report(closeFailure("Disconnect", failure))
                }
            }
        }
    }

    /** Cancel queued/active card work when key custody changes, without replacing UI evidence. */
    fun invalidateForKeyChange() {
        disconnectRequested.set(true)
        pendingRaw.getAndSet(null)?.wipe()
        requestActiveCancellation()
        scope.launch {
            operationGate.withLock {
                try {
                    closeAll()
                } catch (failure: Throwable) {
                    report(closeFailure("Key-source change", failure))
                }
            }
        }
    }

    /** Close ownership and stop accepting work when the ViewModel is permanently cleared. */
    fun shutdown() {
        if (!closing.compareAndSet(false, true)) return
        disconnectRequested.set(true)
        pendingRaw.getAndSet(null)?.wipe()
        requestActiveCancellation()
        scope.launch {
            operationGate.withLock {
                var lastFailure: Throwable? = null
                repeat(3) { attempt ->
                    try {
                        closeAll()
                        return@withLock
                    } catch (failure: Throwable) {
                        lastFailure = failure
                        if (attempt < 2) delay(50)
                    }
                }
                report(closeFailure("Shutdown", checkNotNull(lastFailure)))
            }
            scope.cancel()
        }
    }

    /** Refresh and strictly parse GetVersion on the active managed card. */
    fun readVersion() = managed("GetVersion") { card ->
        VersionReport.parse(card.getVersion()).display()
    }

    /** Read native application identifiers and present complete three-byte values. */
    fun readApplications() = managed("GetApplicationIDs") { card ->
        val bytes = card.applicationIds()
        if (bytes.size % 3 != 0) {
            throw MalformedCardDataException(
                "Application ID response is not a sequence of three-byte IDs.",
            )
        }
        if (bytes.isEmpty()) {
            "No applications reported."
        } else {
            bytes.asList().chunked(3).joinToString(separator = "\n") { aid ->
                val value = aid[0].toInt() and 0xFF or
                    ((aid[1].toInt() and 0xFF) shl 8) or
                    ((aid[2].toInt() and 0xFF) shl 16)
                "AID %06X".format(value)
            }
        }
    }

    /** Read card free-memory evidence without changing card contents. */
    fun readFreeMemory() = managed("FreeMemory") { card -> "${card.freeMemory()} bytes" }

    /** Select a typed native application and retain that selection for displayed prerequisites. */
    fun selectApplication(applicationId: Int) = managed("SelectApplication") { card ->
        card.selectApplication(ApplicationId(applicationId))
        selectedApplication = applicationId
        publishConnection()
        "Selected AID %06X".format(applicationId)
    }

    /** Establish the chosen AES session using one caller-created, session-scoped key source. */
    fun authenticate(
        profile: ExampleAuthenticationProfile,
        keyNumber: Int,
        applicationId: Int?,
        keySource: (ApplicationId?) -> KeySource,
    ) = managed(title = "Authenticate ${profile.name}") { card ->
        val currentApplication = checkNotNull(selectedApplication) {
            "No selected application is available for key scoping."
        }
        check(applicationId == null || applicationId == currentApplication) {
            "Authentication application scope differs from the selected card application."
        }
        val scopedApplication = currentApplication.takeUnless { it == 0 }?.let(::ApplicationId)
        val source = keySource(scopedApplication)
        try {
            val info = when (profile) {
                ExampleAuthenticationProfile.STANDARD_AES -> {
                    card.authenticateStandardAes(KeyNumber(keyNumber), source)
                    null
                }
                ExampleAuthenticationProfile.EV2_FIRST ->
                    card.authenticateEv2FirstAes(KeyNumber(keyNumber), source)
                ExampleAuthenticationProfile.EV2_NON_FIRST ->
                    card.authenticateEv2NonFirstAes(KeyNumber(keyNumber), source)
                ExampleAuthenticationProfile.ISO_AES -> {
                    card.authenticateIsoAes(KeyNumber(keyNumber), scopedApplication != null, source)
                    null
                }
            }
            authenticationResult(info)
        } finally {
            (source as? AutoCloseable)?.close()
        }
    }

    /** List file numbers for the currently selected PICC/application scope. */
    fun readFileIds() = managed("GetFileIDs") { card ->
        val ids = card.fileIds()
        if (ids.isEmpty()) "No native files reported."
        else ids.joinToString { (it.toInt() and 0xFF).toString() }
    }

    /** Read exact settings bytes for one typed native file number. */
    fun readFileSettings(fileNumber: Int) = managed("GetFileSettings") { card ->
        "Settings ${card.getFileSettings(FileNumber(fileNumber)).toHex()}"
    }

    /** Read a bounded region from one native file using the selected communication policy. */
    fun readFile(
        fileNumber: Int,
        offset: Int,
        length: Long,
        communication: Communication,
    ) = managed("ReadData") { card ->
        val bytes = card.readData(
            FileNumber(fileNumber),
            com.desfire.ev3.ByteOffset(offset),
            length,
            communication,
        )
        bytes.toBoundedDisplay()
    }

    /** Dispatch one already-reviewed atomic mutation exactly once. */
    fun executeReviewedTransaction(
        applicationId: Int,
        operation: TransactionOperation,
    ) = managed("ExecuteTransaction", mutation = true) { card ->
        check(selectedApplication == applicationId) {
            "Selected application changed after review; review the transaction again."
        }
        val receipt = card.executeTransaction(listOf(operation), returnMac = false)
        if (receipt.isEmpty()) "Transaction committed; no response payload."
        else "Transaction receipt ${receipt.toHex()}"
    }

    /** Close managed ownership, retain one raw plan, and require a fresh NFC discovery. */
    fun armRaw(plan: RawPlan) {
        requestActiveCancellation()
        scope.launch {
            operationGate.withLock {
                if (disconnectRequested.get()) {
                    plan.wipe()
                    report(localFailure("Raw request", "The foreground reader session is closed."))
                    return@withLock
                }
                try {
                    closeAll()
                } catch (failure: Throwable) {
                    plan.wipe()
                    report(closeFailure("Arm raw request", failure))
                    return@withLock
                }
                pendingRaw.getAndSet(plan)?.wipe()
                report(
                    OperationSnapshot(
                        title = "Raw request armed",
                        detail = "Present one ISO-DEP tag. The request will run once in an exclusive raw channel.",
                    ),
                )
            }
        }
    }

    /** Open one persistent managed session and perform a safe initial GetVersion read. */
    private suspend fun openManaged(tag: Tag) {
        try {
            closeAll()
        } catch (failure: Throwable) {
            report(closeFailure("Connect", failure))
            return
        }
        unknownLocked = false
        val isoDep = IsoDep.get(tag)
        if (isoDep == null) {
            report(localFailure("Connect", "Tag does not expose ISO-DEP."))
            return
        }
        check(openingIsoDep.compareAndSet(null, isoDep)) {
            "Another ISO-DEP connection is still awaiting ownership transfer."
        }
        try {
            isoDep.connect()
            val session = AndroidCardSession.open(isoDep)
            activeSession.set(session)
            check(openingIsoDep.compareAndSet(isoDep, null)) {
                "ISO-DEP opening ownership changed before managed-session transfer."
            }
            check(!disconnectRequested.get()) { "Connection was cancelled before card I/O." }
            selectedApplication = 0
            publishConnection()
            session.card.selectApplication(ApplicationId(0))
            val version = VersionReport.parse(session.card.getVersion())
            report(success("Connected", version.display(), mutation = false))
        } catch (failure: DesfireException) {
            reportSdkFailure("Connect", failure, mutation = false)
            closeAfterFailure("Connect")
        } catch (failure: MalformedCardDataException) {
            reportMalformed("Connect", failure)
            closeAfterFailure("Connect")
        } catch (failure: MalformedNativeResultException) {
            reportMalformedNative("Connect", failure)
            closeAfterFailure("Connect")
        } catch (failure: Throwable) {
            report(localFailure("Connect", failure.message ?: "Could not open ISO-DEP."))
            closeAfterFailure("Connect")
        }
    }

    /** Execute one raw plan through a separately owned channel and preserve exact status. */
    private suspend fun executeRaw(tag: Tag, plan: RawPlan) {
        val isoDep = IsoDep.get(tag)
        if (isoDep == null) {
            plan.wipe()
            report(localFailure("Raw exchange", "Tag does not expose ISO-DEP."))
            return
        }
        unknownLocked = false
        publishConnection()
        check(openingIsoDep.compareAndSet(null, isoDep)) {
            "Another ISO-DEP connection is still awaiting ownership transfer."
        }
        var session: AndroidRawSession? = null
        var transmissionStarted = false
        try {
            isoDep.connect()
            session = AndroidRawSession.open(isoDep)
            activeRawSession.set(session)
            check(openingIsoDep.compareAndSet(isoDep, null)) {
                "ISO-DEP opening ownership changed before raw-session transfer."
            }
            check(!disconnectRequested.get()) { "Raw exchange was cancelled before card I/O." }
            when (plan) {
                is RawPlan.Native -> {
                    val request = NativeRequest(
                        framing = androidNativeFraming,
                        command = plan.command,
                        data = plan.data,
                        maximumResponse = plan.maximumResponse,
                    )
                    try {
                        transmissionStarted = true
                        session.channel.nativeExchange(request).use { response ->
                            val detail = response.useData { it.toBoundedDisplay() }
                            val succeeded = response.status == 0
                            report(
                                OperationSnapshot(
                                    title = "Raw native exchange",
                                    detail = detail,
                                    outcome = if (succeeded) "SUCCEEDED" else "REJECTED",
                                    cardStatus = "0x%02X".format(response.status),
                                    recovery = rawRecovery(succeeded),
                                ),
                            )
                        }
                    } finally {
                        request.close()
                    }
                }
                is RawPlan.Iso -> {
                    val request = IsoApdu(
                        cla = plan.cla,
                        ins = plan.ins,
                        p1 = plan.p1,
                        p2 = plan.p2,
                        data = plan.data,
                        maximumResponse = plan.maximumResponse,
                    )
                    try {
                        transmissionStarted = true
                        session.channel.isoExchange(request).use { response ->
                            val detail = response.useData { it.toBoundedDisplay() }
                            report(
                                OperationSnapshot(
                                    title = "Raw ISO 7816 exchange",
                                    detail = detail,
                                    outcome = if (response.successful) "SUCCEEDED" else "REJECTED",
                                    cardStatus = "0x%04X".format(response.status),
                                    recovery = rawRecovery(response.successful),
                                ),
                            )
                        }
                    } finally {
                        request.close()
                    }
                }
            }
        } catch (failure: DesfireException) {
            reportSdkFailure("Raw exchange", failure, mutation = true)
        } catch (failure: Throwable) {
            if (transmissionStarted) {
                unknownLocked = true
                report(
                    OperationSnapshot(
                        title = "Raw exchange",
                        detail = failure.message ?: "Raw result processing failed after dispatch.",
                        errorCode = "LOCAL_POST_IO_FAILURE",
                        outcome = "UNKNOWN",
                        requiresReconciliation = true,
                        recovery = "Do not retry. Reconcile by the raw opcode's mutation policy.",
                    ),
                )
                publishConnection()
            } else {
                report(localFailure("Raw exchange", failure.message ?: "Raw channel failed."))
            }
        } finally {
            plan.wipe()
            withContext(NonCancellable) {
                try {
                    if (session != null) closeRaw(session) else closeOpeningIsoDep()
                } catch (failure: Throwable) {
                    report(closeFailure("Close raw session", failure))
                }
            }
        }
    }

    /** Serialize one managed action and reject it after unknown delivery or disconnection. */
    private fun managed(
        title: String,
        mutation: Boolean = false,
        operation: suspend (Card) -> String,
    ) {
        scope.launch {
            operationGate.withLock {
                    if (unknownLocked) {
                        report(
                            localFailure(
                                title,
                                "Session is locked after UNKNOWN delivery. " +
                                    "Remove and rediscover the card.",
                            ),
                        )
                        return@withLock
                    }
                    val session = activeSession.get()
                    if (session == null || disconnectRequested.get()) {
                        report(
                            localFailure(
                                title,
                                "Present an ISO-DEP card before running this operation.",
                            ),
                        )
                        return@withLock
                    }
                    try {
                        report(success(title, operation(session.card), mutation))
                    } catch (failure: DesfireException) {
                        reportSdkFailure(title, failure, mutation)
                        if (failure.deliveryOutcome == Outcome.UNKNOWN ||
                            failure.errorCode == ErrorCode.CARD_REMOVED ||
                            failure.errorCode == ErrorCode.TRANSPORT
                        ) {
                            closeAfterFailure(title)
                        }
                    } catch (failure: MalformedCardDataException) {
                        reportMalformed(title, failure)
                    } catch (failure: MalformedNativeResultException) {
                        reportMalformedNative(title, failure)
                        closeAfterFailure(title)
                    } catch (failure: Throwable) {
                        report(
                            localFailure(
                                title,
                                failure.message ?: "Local input validation failed.",
                            ),
                        )
                    }
            }
        }
    }

    /** Close managed JNI and ISO-DEP ownership, retaining recoverable ownership on failure. */
    private suspend fun closeManaged() {
        val session = activeSession.get()
        if (session != null) {
            withContext(NonCancellable) { session.close() }
            check(activeSession.compareAndSet(session, null)) {
                "Managed session ownership changed while closing."
            }
            selectedApplication = null
        }
        publishConnection()
    }

    /** Close raw JNI and ISO-DEP ownership, retaining recoverable ownership on failure. */
    private suspend fun closeRaw(expected: AndroidRawSession? = activeRawSession.get()) {
        if (expected != null) {
            withContext(NonCancellable) { expected.close() }
            check(activeRawSession.compareAndSet(expected, null)) {
                "Raw session ownership changed while closing."
            }
        }
    }

    /** Close every possible owner in deterministic managed-then-raw order. */
    private suspend fun closeAll() {
        closeManaged()
        closeRaw()
        closeOpeningIsoDep()
    }

    /** Report but retain a session when close fails after another operation failure. */
    private suspend fun closeAfterFailure(title: String) {
        try {
            closeAll()
        } catch (failure: Throwable) {
            report(closeFailure("$title cleanup", failure))
        }
    }

    /** Close pre-session ISO-DEP ownership and clear it only after Android confirms release. */
    private fun closeOpeningIsoDep() {
        val isoDep = openingIsoDep.get() ?: return
        isoDep.close()
        check(openingIsoDep.compareAndSet(isoDep, null)) {
            "ISO-DEP opening ownership changed while closing."
        }
    }

    /** Preserve exact SDK evidence and lock after any UNKNOWN delivery. */
    private fun reportSdkFailure(title: String, failure: DesfireException, mutation: Boolean) {
        val unknown = failure.deliveryOutcome == Outcome.UNKNOWN
        if (unknown) unknownLocked = true
        val reconciliation = mutation && unknown
        report(
            OperationSnapshot(
                title = title,
                detail = failure.message ?: "The SDK rejected the operation.",
                errorCode = failure.errorCode?.name ?: "UNKNOWN_VALUE(${failure.code})",
                outcome = failure.deliveryOutcome?.name ?: "UNKNOWN_VALUE(${failure.outcome})",
                cardStatus = "0x%08X".format(failure.deviceStatus),
                requiresReconciliation = reconciliation,
                recovery = when {
                    reconciliation -> "Do not retry. Reconcile card/application state after rediscovery."
                    unknown -> "Rediscover the card before another command; no mutation was requested."
                    else -> "No automatic retry was performed."
                },
            ),
        )
        publishConnection()
    }

    /** Build a checked-success snapshot with mutation-specific receipt guidance. */
    private fun success(
        title: String,
        detail: String,
        mutation: Boolean,
    ): OperationSnapshot = OperationSnapshot(
        title = title,
        detail = detail,
        outcome = "SUCCEEDED",
        cardStatus = "0x00000000 (checked success)",
        recovery = if (mutation) {
            "Mutation completed with checked success; retain the receipt for audit history."
        } else {
            "Read-only operation completed with checked success."
        },
    )

    /** Preserve that card I/O succeeded while rejecting malformed local result decoding. */
    private fun reportMalformed(title: String, failure: MalformedCardDataException) {
        report(
            OperationSnapshot(
                title = title,
                detail = failure.message ?: "Card response failed local structural validation.",
                errorCode = "MALFORMED_RESPONSE",
                outcome = "SUCCEEDED",
                cardStatus = "0x00000000 (command succeeded)",
                recovery = "The card command succeeded; reject the malformed result locally.",
            ),
        )
    }

    /** Preserve checked native success while rejecting a Kotlin ABI result-shape violation. */
    private fun reportMalformedNative(title: String, failure: MalformedNativeResultException) {
        report(
            OperationSnapshot(
                title = title,
                detail = failure.message ?: "Native result violated the Kotlin ABI shape.",
                errorCode = "MALFORMED_NATIVE_RESULT",
                outcome = "SUCCEEDED",
                cardStatus = "0x00000000 (native call succeeded)",
                recovery = "The session was closed; rediscover the card before another command.",
            ),
        )
    }

    /** Explain raw status without claiming semantic knowledge of an arbitrary opcode. */
    private fun rawRecovery(successful: Boolean): String = if (successful) {
        "Raw status indicates success; interpret and retain any mutation receipt by opcode policy."
    } else {
        "The card rejected the raw request. No automatic retry was performed."
    }

    /** Describe retained ownership after a close failure so the user can retry recovery. */
    private fun closeFailure(title: String, failure: Throwable): OperationSnapshot =
        OperationSnapshot(
            title = title,
            detail = failure.message ?: "Reader ownership could not be released.",
            errorCode = "CLOSE_FAILED",
            outcome = "NOT_SENT",
            recovery = "Ownership was retained. Retry disconnect before admitting another tag.",
        )

    /** Build a pre-transmission or local-validation failure snapshot. */
    private fun localFailure(title: String, detail: String): OperationSnapshot = OperationSnapshot(
        title = title,
        detail = detail,
        errorCode = "LOCAL_VALIDATION",
        outcome = "NOT_SENT",
    )

    /** Format public EV2 authentication metadata without showing keys. */
    private fun authenticationResult(info: AuthenticationInfo?): String = if (info == null) {
        "Authentication succeeded. Key material remains redacted."
    } else {
        "Authentication succeeded.\nTransaction ID ${info.transactionIdentifier.toHex()}\n" +
            "PICC capabilities ${info.piccCapabilities.toHex()}\n" +
            "PCD capabilities ${info.pcdCapabilities.toHex()}"
    }

    /** Publish current card ownership and recovery lock state. */
    private fun publishConnection() {
        connectionChanged(
            ConnectionState(
                connected = activeSession.get() != null,
                selectedApplication = selectedApplication,
                unknownLocked = unknownLocked,
            ),
        )
    }

    /** Best-effort interruption tolerates a handle that completed close during this race. */
    private fun requestActiveCancellation() {
        try {
            activeSession.get()?.card?.requestCancellation()
        } catch (_: Throwable) {
            // The queued close path owns the authoritative release result.
        }
        try {
            activeRawSession.get()?.requestCancellation()
        } catch (_: Throwable) {
            // The queued close path owns the authoritative release result.
        }
        try {
            openingIsoDep.get()?.close()
        } catch (_: Throwable) {
            // The queued close path retains the handle and owns the authoritative release result.
        }
    }
}
