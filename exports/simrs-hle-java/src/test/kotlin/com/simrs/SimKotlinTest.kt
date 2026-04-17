///usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS org.junit.jupiter:junit-jupiter:5.12.2
//DEPS org.junit.platform:junit-platform-launcher:1.12.2
//DEPS org.junit.platform:junit-platform-console-standalone:1.12.2

package com.simrs

import org.junit.jupiter.api.Test
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder
import org.junit.platform.launcher.core.LauncherFactory
import org.junit.platform.launcher.listeners.SummaryGeneratingListener
import org.junit.platform.engine.discovery.DiscoverySelectors.selectClass
import org.junit.jupiter.api.Assertions.*
import java.io.PrintWriter

class SimKotlinTest {

    private fun makeSim(): Sim {
        val creds = Credentials(ByteArray(16), ByteArray(16), ByteArray(16))
        return simOf(creds)
    }

    @Test
    fun credentialsValidateKeyLengths() {
        assertThrows(IllegalArgumentException::class.java) {
            Credentials(ByteArray(8), ByteArray(16), ByteArray(16))
        }
    }

    @Test
    fun credentialsEquality() {
        val a = Credentials(ByteArray(16) { 0x11 }, ByteArray(16) { 0x22 }, ByteArray(16) { 0x33 })
        val b = Credentials(ByteArray(16) { 0x11 }, ByteArray(16) { 0x22 }, ByteArray(16) { 0x33 })
        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
    }

    @Test
    fun exchangeDecomposesResponse() {
        val sim = makeSim()
        sim.reset()
        val rsp = sim.exchange(byteArrayOf(0x00, 0xA4.toByte(), 0x00, 0x04, 0x02, 0x3F, 0x00))
        assertEquals(0x61.toByte(), rsp.sw1)
        assertEquals(0x6118, rsp.sw)
        assertFalse(rsp.isSuccess)
    }

    @Test
    fun exchangeHexAcceptsSpaces() {
        val sim = makeSim()
        sim.reset()
        val rsp = sim.exchangeHex("00 A4 00 04 02 3F 00")
        assertEquals(0x61.toByte(), rsp.sw1)
    }

    @Test
    fun hexRoundtrip() {
        val bytes = byteArrayOf(0x3B, 0x9F.toByte(), 0x96.toByte(), 0x80.toByte())
        assertEquals("3B9F9680", bytes.toHex())
        assertArrayEquals(bytes, "3B9F9680".hexToBytes())
    }

    companion object {
        @JvmStatic
        fun main(args: Array<String>) {
            val request = LauncherDiscoveryRequestBuilder.request()
                .selectors(selectClass(SimKotlinTest::class.java))
                .build()
            val listener = SummaryGeneratingListener()
            val launcher = LauncherFactory.create()
            launcher.execute(request, listener)
            val summary = listener.summary
            summary.printTo(PrintWriter(System.out))
            if (summary.totalFailureCount > 0) {
                summary.failures.forEach { it.exception.printStackTrace() }
                System.exit(1)
            }
        }
    }
}
