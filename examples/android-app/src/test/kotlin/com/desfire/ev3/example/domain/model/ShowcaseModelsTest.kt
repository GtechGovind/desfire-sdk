package com.desfire.ev3.example.domain.model

import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** Verify response parsing and display bounds independently of Android NFC. */
class ShowcaseModelsTest {
    /** Classify an invalid successful GetVersion body as malformed card data. */
    @Test
    fun malformedVersionUsesPostIoFailureType() {
        assertThrows(MalformedCardDataException::class.java) { VersionReport.parse(ByteArray(27)) }
    }

    /** Show only a fixed preview while retaining complete size and digest evidence. */
    @Test
    fun responseDisplayIsBounded() {
        val response = ByteArray(1024) { 0x5A }
        val display = response.toBoundedDisplay(32)
        assertTrue(display.contains("1024 byte(s)"))
        assertTrue(display.contains("992 byte(s) omitted"))
        assertTrue(display.contains("SHA-256"))
        assertFalse(display.contains(response.toHex()))
    }
}
