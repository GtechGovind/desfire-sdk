package com.desfire.ev3

import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/** AES implementation supplied by the JVM/Android platform, independent of native OpenSSL. */
private fun aes(key: ByteArray, iv: ByteArray, input: ByteArray, encrypt: Boolean): ByteArray {
    val cipher = Cipher.getInstance("AES/CBC/NoPadding")
    cipher.init(if (encrypt) Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE,
        SecretKeySpec(key, "AES"), IvParameterSpec(iv))
    return cipher.doFinal(input)
}

/** Derive a CMAC subkey in the finite field with reduction polynomial 0x87. */
private fun doubled(input: ByteArray): ByteArray {
    val output = ByteArray(16)
    var carry = 0
    for (index in 15 downTo 0) {
        val value = input[index].toInt() and 255
        output[index] = ((value shl 1) or carry).toByte()
        carry = value ushr 7
    }
    if (carry != 0) output[15] = (output[15].toInt() xor 0x87).toByte()
    return output
}

/** Protect one short fixture response using independently calculated retained-IV CMAC. */
private fun responseMac(key: ByteArray, iv: ByteArray, data: ByteArray): ByteArray {
    check(data.size < 15)
    val secondSubkey = doubled(doubled(aes(key, ByteArray(16), ByteArray(16), true)))
    val block = ByteArray(16)
    data.copyInto(block)
    block[data.size + 1] = 0x80.toByte() // CMAC includes native success byte 00 before padding.
    for (index in block.indices) block[index] = (block[index].toInt() xor secondSubkey[index].toInt()).toByte()
    return aes(key, iv, block, true)
}

/** Emulate the PICC side of ISO mutual AES and two authenticated reads without using SDK crypto. */
internal fun checkNativeIsoAes(
    fixtureKey: ByteArray = ByteArray(16),
    keySource: KeySource = KeySource.Direct(fixtureKey),
) {
    val cardFirst = ByteArray(16) { (it + 1).toByte() }
    val cardSecond = ByteArray(16) { (it + 65).toByte() }
    var hostFirst = ByteArray(0)
    var proofIv = ByteArray(0)
    var sessionKey = ByteArray(0)
    var retainedIv = ByteArray(16)
    var step = 0
    val transport = object : CardTransport {
        override val limits = TransportLimits()

        /** Validate real OpenSSL proofs and return independently encrypted card authentication. */
        override fun exchange(frame: ByteArray, timeoutMs: Int): ByteArray {
            check(timeoutMs > 0 && frame[0] == 0.toByte())
            val response = when (step++) {
                0 -> {
                    check(frame.contentEquals(byteArrayOf(0, 0x84.toByte(), 0, 0, 16)))
                    cardFirst
                }
                1 -> {
                    check(frame.size == 37 && frame[1] == 0x82.toByte() && frame[2] == 9.toByte())
                    val encrypted = frame.copyOfRange(5, 37)
                    val proof = aes(fixtureKey, ByteArray(16), encrypted, false)
                    check(proof.copyOfRange(16, 32).contentEquals(cardFirst))
                    hostFirst = proof.copyOfRange(0, 16)
                    proofIv = encrypted.copyOfRange(16, 32)
                    ByteArray(0)
                }
                2 -> {
                    check(frame.size == 22 && frame[1] == 0x88.toByte() && frame[2] == 9.toByte())
                    check(frame.last() == 32.toByte())
                    sessionKey = hostFirst.copyOfRange(0, 4) + cardSecond.copyOfRange(0, 4) +
                        hostFirst.copyOfRange(12, 16) + cardSecond.copyOfRange(12, 16)
                    aes(fixtureKey, proofIv, cardSecond + frame.copyOfRange(5, 21), true)
                }
                3, 4 -> {
                    check(frame.contentEquals(byteArrayOf(0, 0xb0.toByte(), 0,
                        if (step == 4) 0 else 4, 4)))
                    val payload = byteArrayOf(1, 2, 3, step.toByte())
                    retainedIv = responseMac(sessionKey, retainedIv, payload)
                    payload + retainedIv.copyOfRange(0, 8)
                }
                else -> error("Unexpected authenticated ISO frame")
            }
            return response + byteArrayOf(0x90.toByte(), 0)
        }

        /** No asynchronous exchange exists in this fixture. */
        override fun cancel() = Unit
        /** No reconnect is needed by this in-memory fixture. */
        override fun reset() = Unit
    }
    BlockingCard.open(transport).use { card ->
        card.authenticateIsoAes(KeyNumber(0), false, keySource)
        check(card.isoReadBinary(-1, ByteOffset(0), 4).contentEquals(byteArrayOf(1, 2, 3, 4)))
        check(card.isoReadBinary(-1, ByteOffset(4), 4).contentEquals(byteArrayOf(1, 2, 3, 5)))
    }
    check(step == 5)
}
