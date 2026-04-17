package com.simrs

/**
 * Kotlin conveniences for [Sim]. The existing Java class is fully usable
 * from Kotlin; this file adds idiomatic wrappers.
 */

/** SIM authentication credentials. */
data class Credentials(val ki: ByteArray, val k: ByteArray, val opc: ByteArray) {
    init {
        require(ki.size == 16) { "ki must be 16 bytes, got ${ki.size}" }
        require(k.size == 16) { "k must be 16 bytes, got ${k.size}" }
        require(opc.size == 16) { "opc must be 16 bytes, got ${opc.size}" }
    }

    override fun equals(other: Any?) = other is Credentials
        && ki.contentEquals(other.ki)
        && k.contentEquals(other.k)
        && opc.contentEquals(other.opc)

    override fun hashCode(): Int {
        var result = ki.contentHashCode()
        result = 31 * result + k.contentHashCode()
        result = 31 * result + opc.contentHashCode()
        return result
    }
}

/** APDU response decomposed into data and status word. */
data class ApduResponse(val data: ByteArray, val sw1: Byte, val sw2: Byte) {
    /** Status word as a 16-bit integer (SW1 << 8 | SW2). */
    val sw: Int get() = ((sw1.toInt() and 0xFF) shl 8) or (sw2.toInt() and 0xFF)

    /** True if SW is 9000 (normal completion). */
    val isSuccess: Boolean get() = sw == 0x9000

    override fun equals(other: Any?) = other is ApduResponse
        && data.contentEquals(other.data)
        && sw1 == other.sw1
        && sw2 == other.sw2

    override fun hashCode(): Int {
        var result = data.contentHashCode()
        result = 31 * result + sw1
        result = 31 * result + sw2
        return result
    }
}

/** Construct a [Sim] from a [Credentials] instance. */
fun simOf(credentials: Credentials): Sim = Sim(credentials.ki, credentials.k, credentials.opc)

/** Send an APDU and decompose the response into data + SW1 + SW2. */
fun Sim.exchange(command: ByteArray): ApduResponse {
    val raw = apdu(command)
    return ApduResponse(
        data = raw.copyOfRange(0, raw.size - 2),
        sw1 = raw[raw.size - 2],
        sw2 = raw[raw.size - 1],
    )
}

/** Send an APDU from a hex string. Spaces are stripped. */
fun Sim.exchangeHex(hex: String): ApduResponse = exchange(hex.replace(" ", "").hexToBytes())

/** Parse a hex string to bytes. */
fun String.hexToBytes(): ByteArray {
    val s = this.replace(" ", "")
    require(s.length % 2 == 0) { "hex string must have even length" }
    return ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}

/** Format bytes as uppercase hex. */
fun ByteArray.toHex(): String = joinToString("") { "%02X".format(it) }
