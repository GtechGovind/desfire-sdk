package com.desfire.ev3

/** Native three-byte application identifier; zero is the PICC. */
data class ApplicationId(val value: Int) { init { require(value in 0..0xFFFFFF) } }

/** EV3 native five-bit file number, distinct from a two-byte ISO file identifier. */
data class FileNumber(val value: Int) { init { require(value in 0..31) } }

/** Native key reference. Individual commands apply stricter PICC/application limits. */
data class KeyNumber(val value: Int) { init { require(value in 0..63) } }

/** Non-negative byte offset; ISO addressing additionally checks its narrower field limits. */
data class ByteOffset(val value: Int) { init { require(value in 0..0xFFFFFF) } }

/** Four packed access-right nibbles, in native little-endian representation on the wire. */
data class AccessRights(val value: Int) { init { require(value in 0..0xFFFF) } }

/** ISO file identifier, encoded most significant byte first by SELECT FILE. */
data class IsoFileIdentifier(val value: Int) { init { require(value in 0..0xFFFF) } }

/** Command-specific native communication policy; FULL requires verified authentication. */
enum class Communication(val value: Int) { PLAIN(0), MAC(1), FULL(3) }

/** ISO FID selection scopes. EF selection retains authentication. */
enum class IsoFileSelection(val value: Int) { BY_IDENTIFIER(0), CHILD_DF(1), ELEMENTARY_FILE(2) }

/** ISO SELECT FILE response policy. */
enum class IsoSelectionResponse(val value: Int) { FCI(0), NONE(12) }

/** Absolute record or record-through-end ISO read policy. */
enum class IsoRecordSelection(val value: Int) { ONE(4), FROM_RECORD(5) }

/** Algorithm reference for actual ISO authentication primitives. */
enum class IsoAlgorithm(val value: Int) { CONTEXT(0), TDES2(2), TDES3(4), AES128(9) }
