package com.desfire.ev3

import com.desfire.ev3.raw.BlockingRawChannel
import com.desfire.ev3.raw.IsoApdu
import com.desfire.ev3.raw.isoExchange
import com.desfire.ev3.raw.nativeFrame
import com.desfire.ev3.offline.calculateDelegatedApplicationDeleteMacAes
import com.desfire.ev3.offline.calculateDelegatedApplicationMacAes
import com.desfire.ev3.offline.calculateDelegatedConfigurationMacAes
import com.desfire.ev3.offline.calculateMifareClassicLicenseMacAes
import com.desfire.ev3.offline.calculateTransactionMacAes
import com.desfire.ev3.offline.calculateTransactionMacSessionAes
import com.desfire.ev3.offline.decryptTransactionReaderIdAes
import com.desfire.ev3.offline.deriveNxpAes128
import com.desfire.ev3.offline.deriveTransactionMacKeysAes
import com.desfire.ev3.offline.verifyOriginalityUidSignature
import com.desfire.ev3.offline.verifyTransactionMacAes
import java.util.ArrayDeque
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.runBlocking

/** Decode fixed non-secret wire expectations independently of native framing logic. */
private fun hex(value: String): ByteArray =
    value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

/** Fixed physical exchanges; each successful call consumes exactly one expectation. */
private class Replay(private val script: ArrayDeque<Pair<ByteArray, ByteArray>>) : CardTransport {
    override val limits = TransportLimits()
    var cancelled = false

    override fun exchange(frame: ByteArray, timeoutMs: Int): ByteArray {
        check(timeoutMs > 0)
        check(script.isNotEmpty()) { "Unexpected reader exchange" }
        val expected = script.removeFirst()
        check(frame.contentEquals(expected.first)) { "Reader wire mismatch" }
        return expected.second.copyOf()
    }

    override fun cancel() { cancelled = true }
    override fun reset() = Unit
    fun complete() = check(script.isEmpty()) { "Missing reader exchange" }
}

/** Require one structured error without accepting a collapsed runtime exception. */
private fun expectError(code: Int, outcome: Outcome, action: () -> Unit) {
    try {
        action()
        error("Expected native error")
    } catch (failure: DesfireException) {
        check(failure.code == code && failure.outcome == outcome.code) {
            "Unexpected error ${failure.code}/${failure.outcome}"
        }
    }
}

/** Exercise Kotlin -> JNI -> C -> core -> Java transport for native and true ISO operations. */
private fun checkRoundTrip() {
    val replay = Replay(ArrayDeque(listOf(
        hex("905a00000301000000") to hex("9100"),
        hex("906e000000") to hex("0020009100"),
        hex("90bd0000070100000004000000") to hex("aabbccdd9100"),
        hex("906d000000") to hex("9100"),
        hex("00a4020c02e103") to hex("9000"),
        hex("00b0000004") to hex("010203049000"),
    )))
    val card = BlockingCard.open(replay)
    card.selectApplication(ApplicationId(1))
    check(card.freeMemory() == 8192L)
    check(card.readData(FileNumber(1), ByteOffset(0), 4, Communication.PLAIN)
        .contentEquals(hex("aabbccdd")))
    check(card.getDfNames().isEmpty())
    check(card.isoSelectFile(IsoFileIdentifier(0xE103), IsoFileSelection.ELEMENTARY_FILE,
        IsoSelectionResponse.NONE).isEmpty())
    check(card.isoReadBinary(-1, ByteOffset(0), 4).contentEquals(hex("01020304")))
    expectError(ErrorCode.INVALID_ARGUMENT.code, Outcome.NOT_SENT) { card.freeMemory(-1) }
    card.resetAuthentication()
    card.cancel()
    check(replay.cancelled)
    replay.complete()
    card.close()
    card.close()
    expectError(ErrorCode.STALE_HANDLE.code, Outcome.NOT_SENT) { card.freeMemory() }
}

/** Preserve callback evidence and reject callback-triggered recursive close without hanging. */
private fun checkCallbackFailure() {
    var card: BlockingCard? = null
    val transport = object : CardTransport {
        override val limits = TransportLimits()
        override fun exchange(frame: ByteArray, timeoutMs: Int): ByteArray {
            expectError(ErrorCode.BUSY.code, Outcome.NOT_SENT) { card!!.close() }
            throw DesfireException(ErrorCode.TIMEOUT.code, Outcome.UNKNOWN.code, 0,
                "fixture timeout")
        }
        override fun cancel() = Unit
        override fun reset() = Unit
    }
    card = BlockingCard.open(transport)
    expectError(ErrorCode.TIMEOUT.code, Outcome.UNKNOWN) { card.freeMemory() }
    card.close()
}

/** Verify the blocking facade queues complete native operations FIFO instead of surfacing BUSY. */
private fun checkBlockingFifo() {
    val entered = CountDownLatch(1)
    val release = CountDownLatch(1)
    val calls = AtomicInteger()
    val failure = AtomicReference<Throwable?>()
    val transport = object : CardTransport {
        override val limits = TransportLimits()
        override fun exchange(frame: ByteArray, timeoutMs: Int): ByteArray {
            check(frame.contentEquals(hex("906e000000")))
            val current = calls.incrementAndGet()
            if (current == 1) {
                entered.countDown()
                check(release.await(5, TimeUnit.SECONDS))
            }
            return hex("0100009100")
        }
        override fun cancel() = Unit
        override fun reset() = Unit
    }
    val card = BlockingCard.open(transport)
    val first = Thread {
        try { check(card.freeMemory() == 1L) } catch (problem: Throwable) { failure.set(problem) }
    }
    val second = Thread {
        try { check(card.freeMemory() == 1L) } catch (problem: Throwable) { failure.set(problem) }
    }
    first.start()
    check(entered.await(5, TimeUnit.SECONDS))
    second.start()
    Thread.sleep(100)
    check(calls.get() == 1) { "Second operation reached native code before FIFO admission" }
    release.countDown()
    first.join()
    second.join()
    failure.get()?.let { throw it }
    check(calls.get() == 2)
    card.close()
}

/** Verify cancellation reaches an active callback and close safely waits for its return. */
private fun checkConcurrentCancellation() {
    val entered = CountDownLatch(1)
    val cancelled = CountDownLatch(1)
    val failure = AtomicReference<Throwable?>()
    val transport = object : CardTransport {
        override val limits = TransportLimits()
        override fun exchange(frame: ByteArray, timeoutMs: Int): ByteArray {
            entered.countDown()
            check(cancelled.await(5, TimeUnit.SECONDS))
            throw DesfireException(ErrorCode.CANCELLED.code, Outcome.UNKNOWN.code, 0,
                "fixture cancellation")
        }
        override fun cancel() { cancelled.countDown() }
        override fun reset() = Unit
    }
    val card = BlockingCard.open(transport)
    val worker = Thread {
        try { expectError(ErrorCode.CANCELLED.code, Outcome.UNKNOWN) { card.freeMemory() } }
        catch (problem: Throwable) { failure.set(problem) }
    }
    worker.start()
    check(entered.await(5, TimeUnit.SECONDS))
    card.cancelActive()
    card.close()
    worker.join()
    failure.get()?.let { throw it }
}

/** Verify queued coroutine cancellation performs no reader or native operation. */
private fun checkSuspendQueueCancellation() = runBlocking {
    val entered = CountDownLatch(1)
    val release = CountDownLatch(1)
    val calls = AtomicInteger()
    val transport = object : CardTransport {
        override val limits = TransportLimits()
        override fun exchange(frame: ByteArray, timeoutMs: Int): ByteArray {
            calls.incrementAndGet()
            entered.countDown()
            check(release.await(5, TimeUnit.SECONDS))
            return hex("0100009100")
        }
        override fun cancel() = Unit
        override fun reset() = Unit
    }
    val card = Card.open(transport)
    val first = async(Dispatchers.Default) { card.freeMemory() }
    check(entered.await(5, TimeUnit.SECONDS))
    val queued = async(Dispatchers.Default) { card.freeMemory() }
    queued.cancelAndJoin()
    check(calls.get() == 1)
    release.countDown()
    check(first.await() == 1L)
    card.close()
}

/** Verify provider failure stays NOT_SENT and produces no card exchange. */
private fun checkProviderFailure() {
    val calls = AtomicInteger()
    val transport = object : CardTransport {
        override val limits = TransportLimits()
        override fun exchange(frame: ByteArray, timeoutMs: Int): ByteArray {
            calls.incrementAndGet()
            error("Provider failure must precede card I/O")
        }
        override fun cancel() = Unit
        override fun reset() = Unit
    }
    val source = KeySource.Provider(KeyProvider { byteArrayOf(1, 2, 3) }, byteArrayOf(7))
    BlockingCard.open(transport).also { card ->
        expectError(ErrorCode.CRYPTO.code, Outcome.NOT_SENT) {
            card.authenticateStandardAes(KeyNumber(0), source)
        }
        card.close()
    }
    check(calls.get() == 0)

    val replacement = KeySource.Provider(KeyProvider { request ->
        check(request.purpose == KeyPurpose.REPLACEMENT_KEY)
        check(request.profile == null)
        throw IllegalStateException("fixture provider failure")
    }, byteArrayOf(8))
    BlockingCard.open(transport).also { card ->
        expectError(ErrorCode.CRYPTO.code, Outcome.NOT_SENT) {
            card.setDefaultAesKey(replacement, version = 1)
        }
        card.close()
    }
    check(calls.get() == 0)
}

/** Verify independent raw native and ISO status preservation. */
private fun checkRawChannels() {
    val nativeReplay = Replay(ArrayDeque(listOf(hex("9060000000") to hex("9100"))))
    BlockingRawChannel.open(nativeReplay).also { channel ->
        val response = channel.nativeFrame(Framing.ISO_WRAPPED, 0x60)
        check(response.status == 0 && response.data.isEmpty())
        channel.close()
    }
    nativeReplay.complete()

    val isoReplay = Replay(ArrayDeque(listOf(
        hex("0084000008") to (hex("0102030405060708") + hex("9000")),
    )))
    BlockingRawChannel.open(isoReplay).also { channel ->
        val response = channel.isoExchange(IsoApdu(0, 0x84, 0, 0, le = 8))
        check(response.status == 0x9000)
        check(response.data.contentEquals(hex("0102030405060708")))
        channel.close()
    }
    isoReplay.complete()
}

/** Verify every deterministic offline JNI family against independent published test material. */
private fun checkOfflineAes() {
    val master = hex("00112233445566778899aabbccddeeff")
    val diversification = hex("04782e21801d803042f54e585020416275")
    check(deriveNxpAes128(master, diversification)
        .contentEquals(hex("a8dd63a3b89d54b37ca802473fda9175")))

    val provider = KeySource.Provider(KeyProvider { request ->
        check(request.purpose == KeyPurpose.OFFLINE_OPERATION)
        check(request.profile == null)
        check(request.keyNumber == KeyNumber(0))
        master
    }, "offline-master".encodeToByteArray(), diversification)
    check(deriveNxpAes128(provider)
        .contentEquals(hex("a8dd63a3b89d54b37ca802473fda9175")))

    val damKey = hex("11111111111111111111111111111111")
    val encrypted = hex("9232C82A913FA1CFCDC7ED5EC63AB45CE991C06A1F485156DB8C3CDCB689BD27")
    val delegated = DelegatedApplication(
        ApplicationId(0x563412), 0xEF, 1, 0, 0, 0x40, false,
        encryptedDefaultKey = encrypted, damMac = ByteArray(8),
    )
    check(calculateDelegatedApplicationMacAes(damKey, delegated, encrypted)
        .contentEquals(hex("5D941683B901612B")))
    check(calculateDelegatedApplicationDeleteMacAes(damKey, 0x563412)
        .contentEquals(hex("DCD2F30E702C9370")))
    check(calculateDelegatedConfigurationMacAes(
        damKey, hex("A0000003965643"), hex("A0000003965644"),
    ).contentEquals(hex("D28CA69A54454B38")))
    check(calculateMifareClassicLicenseMacAes(
        master, hex("0204A108B2"),
        hex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
    ).contentEquals(hex("766EDC8921F03E2E")))

    val uid = hex("04782E21801D80")
    val sessionKeys = deriveTransactionMacKeysAes(master, 1, uid)
    check(sessionKeys.contentEquals(hex(
        "2DB206D20F493AC4524EADE977E976B4A0DD3EA52546EC462FE0F466FEB3A62F",
    )))
    val tmi = hex("3D0200000003000000000000000000000010203000000000000000000000000000")
    val expectedMac = hex("1E285E485BA62DE1")
    check(calculateTransactionMacSessionAes(sessionKeys.copyOfRange(0, 16), tmi)
        .contentEquals(expectedMac))
    check(calculateTransactionMacAes(master, 1, uid, tmi).contentEquals(expectedMac))
    val transactionProvider = KeySource.Provider(KeyProvider { request ->
        check(request.purpose == KeyPurpose.TRANSACTION_MAC)
        check(request.profile == null)
        master
    }, "transaction-key".encodeToByteArray())
    check(calculateTransactionMacAes(
        transactionProvider, transactionCounter = 1, uid = uid, transactionInput = tmi,
    ).contentEquals(expectedMac))
    check(verifyTransactionMacAes(master, 1, uid, tmi, expectedMac))
    check(!verifyTransactionMacAes(master, 2, uid, tmi, expectedMac))
    check(decryptTransactionReaderIdAes(
        sessionKeys.copyOfRange(16, 32), hex("4CBA5402F5723FA30DFCDF9477E623F5"),
    ).contentEquals(hex("00112233445566778899AABBCCDDEEFF")))

    val publicKey = hex("040E98E117AAA36457F43173DC920A8757267F44CE4EC5ADD3C5407557" +
        "1AEBBF7B942A9774A1D94AD02572427E5AE0A2DD36591B1FB34FCF3D")
    val signature = hex("1CA298FC3F0F04A329254AC0DF7A3EB8E756C076CD1BAAF47B8BBA6D" +
        "CD78BCC64DFD3E80E679D9A663CAE9E4D4C2C77023077CC549CE4A61")
    check(verifyOriginalityUidSignature(publicKey, hex("045A115A346180"), signature))
}

/** Execute deterministic host/JNI coverage without physical hardware or production keys. */
public fun main() {
    checkRoundTrip()
    checkCallbackFailure()
    checkBlockingFifo()
    checkConcurrentCancellation()
    checkSuspendQueueCancellation()
    checkProviderFailure()
    checkRawChannels()
    checkOfflineAes()
    checkNativeIsoAes()
    val providerKey = ByteArray(16)
    checkNativeIsoAes(providerKey, KeySource.Provider(KeyProvider { request ->
        check(request.profile == AuthenticationProfile.ISO_AES)
        check(request.purpose == KeyPurpose.AUTHENTICATION)
        check(request.scope == KeyScope.ISO_PICC)
        check(request.keyNumber == KeyNumber(0))
        check(!request.cancellationRequested)
        providerKey
    }, "fixture-key".encodeToByteArray()))
    val master = hex("00112233445566778899aabbccddeeff")
    val diversification = hex("04782e21801d803042f54e585020416275")
    val derived = hex("a8dd63a3b89d54b37ca802473fda9175")
    checkNativeIsoAes(derived, KeySource.Derived(master, diversification))
    println("EV3 Kotlin/JNI host tests passed")
}
