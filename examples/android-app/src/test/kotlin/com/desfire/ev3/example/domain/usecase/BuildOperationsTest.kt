package com.desfire.ev3.example.domain.usecase

import com.desfire.ev3.Communication
import com.desfire.ev3.TransactionOperation
import com.desfire.ev3.example.domain.model.RawKind
import com.desfire.ev3.example.domain.model.RawPlan
import com.desfire.ev3.example.domain.model.TransactionKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** Verify that high-risk UI input becomes fixed, bounded SDK requests before dispatch. */
class BuildOperationsTest {
    /** Build all seven typed transaction variants and preserve their selected type. */
    @Test
    fun buildsEveryTransactionVariant() {
        val expected = mapOf(
            TransactionKind.CREDIT to TransactionOperation.Credit::class,
            TransactionKind.DEBIT to TransactionOperation.Debit::class,
            TransactionKind.LIMITED_CREDIT to TransactionOperation.LimitedCredit::class,
            TransactionKind.WRITE_DATA to TransactionOperation.WriteData::class,
            TransactionKind.WRITE_RECORD to TransactionOperation.WriteRecord::class,
            TransactionKind.UPDATE_RECORD to TransactionOperation.UpdateRecord::class,
            TransactionKind.CLEAR_RECORD_FILE to TransactionOperation.ClearRecordFile::class,
        )
        expected.forEach { (kind, type) ->
            val review = review(kind, "0102")
            assertEquals(type, review.operation::class)
            assertTrue(review.description.contains("AID 010203"))
        }
    }

    /** Display the command-fixed plain mode instead of an ignored UI communication choice. */
    @Test
    fun clearRecordReviewUsesFixedPlainCommunication() {
        val review = review(TransactionKind.CLEAR_RECORD_FILE, "", Communication.FULL)
        assertTrue(review.description.contains("PLAIN (fixed by command)"))
        assertTrue(review.operation is TransactionOperation.ClearRecordFile)
    }

    /** Identify exact same-length write payloads independently in the final review. */
    @Test
    fun writeReviewIncludesExactDataDigest() {
        val first = review(TransactionKind.WRITE_DATA, "0102").description
        val second = review(TransactionKind.WRITE_DATA, "0103").description
        assertTrue(first.contains("data SHA-256"))
        assertNotEquals(first, second)
    }

    /** Normalize raw headers, copy data, and enforce the 64 KiB display bound. */
    @Test
    fun buildsBoundedRawPlans() {
        val native = buildRawPlan(RawKind.NATIVE, "60", "0102", "65536")
        assertTrue(native is RawPlan.Native)
        native as RawPlan.Native
        assertEquals(0x60, native.command)
        assertEquals(65_536L, native.maximumResponse)

        val iso = buildRawPlan(RawKind.ISO_7816, "00 A4 02 0C", "E103", "16")
        assertTrue(iso is RawPlan.Iso)
        iso as RawPlan.Iso
        assertEquals(0xA4, iso.ins)
        assertThrows(IllegalArgumentException::class.java) {
            buildRawPlan(RawKind.NATIVE, "60", "", "65537")
        }
        assertThrows(IllegalArgumentException::class.java) {
            buildRawPlan(RawKind.NATIVE, "0011223344", "", "1")
        }
        assertThrows(IllegalArgumentException::class.java) {
            buildRawPlan(RawKind.NATIVE, "60", "AA".repeat(65_537), "1")
        }
    }

    /** Accept decimal and hexadecimal forms while rejecting out-of-range values. */
    @Test
    fun parsesBoundedNumbers() {
        assertEquals(255L, parseNumber("0xFF", 0L..255L, "value"))
        assertEquals(255L, parseNumber("255", 0L..255L, "value"))
        assertThrows(IllegalArgumentException::class.java) {
            parseNumber("256", 0L..255L, "value")
        }
    }

    /** Build one transaction review using stable valid defaults. */
    private fun review(
        kind: TransactionKind,
        data: String,
        communication: Communication = Communication.FULL,
    ) = buildTransactionReview(
        applicationIdText = "0x010203",
        kind = kind,
        fileNumberText = "1",
        offsetText = "2",
        recordNumberText = "3",
        amountText = "4",
        dataText = data,
        communication = communication,
    )
}
