/**
 * Copyright (c) 1998, 2025, Oracle and/or its affiliates. All rights reserved.
 */
package com.oracle.javacard.sample;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import java.util.stream.IntStream;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

import com.oracle.javacard.ams.AMService;
import com.oracle.javacard.ams.AMServiceFactory;
import com.oracle.javacard.ams.config.AID;
import com.oracle.javacard.ams.config.CAPFile;
import com.oracle.javacard.ams.script.APDUScript;
import com.oracle.javacard.ams.script.ScriptFailedException;
import com.oracle.javacard.ams.script.Scriptable;

public class ClientObjectDeletion {

    private final static String sAID_ISD     = "aid:A000000151000000";

    private final static String sAIDPackageLibC = "aid:A00000006203010C0703";

    private final static String sAIDPackageA    = "aid:A00000006203010C0701";
    private final static String sAIDAppletA     =  sAIDPackageA + "01";
    private final static String sAIDAppletAInst =  sAIDPackageA + "01";

    private final static String sAIDPackageB    = "aid:A00000006203010C0702";
    private final static String sAIDAppletB     =  sAIDPackageB + "01";
    private final static String sAIDAppletB1st  =  sAIDPackageB + "01";
    private final static String sAIDAppletB2nd  =  sAIDPackageB + "02";

    private static AMService ams = null;

    private final static ResponseAPDU responseOK = new ResponseAPDU(new byte[] { (byte)0x90, (byte)0x00 } );

    private final static CommandAPDU apduSelectAppletA    = new CommandAPDU(0x00, 0xA4, 0x04, 0x00, AID.from(sAIDAppletAInst).toBytes(), 0x7F);
    private final static CommandAPDU apduSelectAppletB2nd = new CommandAPDU(0x00, 0xA4, 0x04, 0x00, AID.from(sAIDAppletB2nd).toBytes(), 0x7F);

    private static CAPFile appFile_A = null;
    private static CAPFile appFile_B = null;
    private static CAPFile appFile_C = null;

    private static String HOST_DEFAULT = "socket:localhost:9025";

    /**
     * Launch the sample
     *
     * @param args command line arguments.<br>
     * Use {@code
     * -capA=<capfile_A>
     * -capB=<capfile_B>
     * -capC=<capfile_C>
     * -props=<property file>}
     */
    public static void main(String[] args) {

        int iResult = 0;

        try {
            // Application binaries needed for execution
            appFile_A = CAPFile.from(getArg(args, "capA", null));
            appFile_B = CAPFile.from(getArg(args, "capB", null));
            appFile_C = CAPFile.from(getArg(args, "capC", null));

            // Configuration stage for connection to simulator
            Properties props   = new Properties();
            props.load(new FileInputStream(getArg(args, "props", null)));

            ams = AMServiceFactory.getInstance("GP2.2");
            ams.setProperties(props);
            for (String key : ams.getPropertiesKeys()) {
                System.out.println(key + " = " + ams.getProperty(key));
            }

            // Terminal to simulator
            CardTerminal terminal = getTerminal(getArg(args, "host", HOST_DEFAULT).split(":"));

            // With a valid terminal wait some seconds to allow connections
            if (terminal != null && terminal.waitForCardPresent(10000)) {
                System.out.println("Connection to simulator established: "+ terminal.getName());
                Card card = terminal.connect("*");
                System.out.println(getFormattedATR(card.getATR().getBytes()));
                testOD_Preparation(card);
                card.disconnect(true);
                card = terminal.connect("*");
                testOD_Exec_1_1(card);
                testOD_Exec_1_2(card);

                card.disconnect(true);
            }
            else {
                System.out.println("Connection to simulator failed");
                iResult = -1;
            }

        }
        catch (NoSuchAlgorithmException | NoSuchProviderException | CardException | ScriptFailedException | IOException e) {
            e.printStackTrace();
            iResult = -1;
        }
        System.exit (iResult);
    }

    /**
     * Preparation stage
     *
     * @param card
     * @throws ScriptFailedException
     * @throws IOException
     * @throws IllegalArgumentException
     */
    private static void testOD_Preparation (Card card) throws ScriptFailedException, IllegalArgumentException, IOException {

        TestScript scriptPrepare = new TestScript()
            // AM session
            .append (
                // select SD & open secure channel
                ams.openSession(sAID_ISD)
                // Load package A
                .load(sAIDPackageA, appFile_A.getBytes())
                // Install applet A
                .install(sAIDPackageA, sAIDAppletA, sAIDAppletAInst)
                .close())
            // Select applet A
            .append(apduSelectAppletA, responseOK)
            // Request "Object Deletion"
            .append(new CommandAPDU(0x80, 0x10, 0x00, 0x00, 0x7F), responseOK)
            // Set-up "transient"
            .append(new CommandAPDU(0x80, 0x20, 0x00, 0x00, 0x7F), responseOK)
            // Set-up "persistent"
            .append(new CommandAPDU(0x80, 0x19, 0x00, 0x00, 0x7F), responseOK)
            // Call "remove trees"
            .append(new CommandAPDU(0x80, 0x11, 0x00, 0x00, 0x7F), responseOK)
            // Request "Object Deletion"
            .append(new CommandAPDU(0x80, 0x10, 0x00, 0x00, 0x7F), responseOK)
            // Analyze "remove trees"
            .append(new CommandAPDU(0x80, 0x12, 0x00, 0x00, 0x7F), responseOK)
            // De-select applet A's instance by selecting it again
            .append(apduSelectAppletA, responseOK)
            // Request "Object Deletion"
            .append(new CommandAPDU(0x80, 0x10, 0x00, 0x00, 0x7F), responseOK)
            // Analyze "transient deselect memory" gone
            .append(new CommandAPDU(0x80, 0x13, 0x00, 0x00, 0x7F), responseOK);

        List<ResponseAPDU> responses = scriptPrepare.run(card.getBasicChannel());
        System.out.println("Responses count: " + responses.size());
    }

    /**
     * Object deletion - Execution, part 1
     *
     * @param card
     * @throws ScriptFailedException
     */
    private static void testOD_Exec_1_1 (Card card) throws ScriptFailedException {

        TestScript script = new TestScript()
            // Select applet A
            .append(apduSelectAppletA, responseOK)
            // Request "Object Deletion"
            .append(new CommandAPDU(0x80, 0x10, 0x00, 0x00, 0x7F), responseOK)
            // Verify "reset memory" gone
            .append(new CommandAPDU(0x80, 0x14, 0x00, 0x00, 0x7F), responseOK)
            // Set all attributes (including transient arrays) to null. This also requests GC
            .append(new CommandAPDU(0x80, 0x15, 0x00, 0x00, 0x7F), responseOK);

        List<ResponseAPDU> responses = script.run(card.getBasicChannel());
        System.out.println("Responses count: " + responses.size());
    }

    /**
     * Object deletion - Execution, part 2
     *
     * @param card
     * @throws ScriptFailedException
     * @throws IOException
     * @throws IllegalArgumentException
     */
    private static void testOD_Exec_1_2 (Card card) throws ScriptFailedException, IllegalArgumentException, IOException {

        TestScript script = new TestScript()
            // Select applet A
            .append(apduSelectAppletA, responseOK)
            // Analyze if all attributes are gone
            .append(new CommandAPDU(0x80, 0x16, 0x00, 0x00, 0x7F), responseOK)
            // Demonstrate some loading / unloading
            .append(
                // Select SD & open secure channel
                ams.openSession(sAID_ISD)
                // Delete applet A's instance - this should work
                .uninstall(sAIDAppletA)
                // Load package C
                .load(sAIDPackageLibC, appFile_C.getBytes())
                // Load package B
                .load(sAIDPackageB, appFile_B.getBytes())
                // Re-install applet again for mem monitoring and capture initial memory, too
                .install(sAIDPackageA, sAIDAppletA, sAIDAppletAInst)
                // Install applet B - first instance
                .install(sAIDPackageB, sAIDAppletB, sAIDAppletB1st)
                // Install applet B - second instance
                .install(sAIDPackageB, sAIDAppletB, sAIDAppletB2nd)
                .close())
            // Select applet A
            .append(apduSelectAppletA, responseOK)
            // Make applet A's instance get a sharable reference to applet B's first instance
            .append(new CommandAPDU(0x80, 0x21, 0x00, 0x00, 0x7F), responseOK)
            // Select applet A
            .append(apduSelectAppletA, responseOK)
            // Lose reference from A (also calls Object Deletion)
            .append(new CommandAPDU(0x80, 0x22, 0x00, 0x00, 0x7F), responseOK)
            // Select applet B's second instance
            .append(apduSelectAppletB2nd, responseOK)
            // Introduce reference from Applet B's first instance to Applet B's second instance
            .append(new CommandAPDU(0x80, 0x12, 0x00, 0x00, 0x7F), responseOK)
            // AM session
            .append(
                // Select SD & open secure channel
                ams.openSession(sAID_ISD)
                // Try to delete applet B's second instance - success expected
                .uninstall(sAIDAppletB2nd)
                // Try to delete applet B's first instance success expected
                .uninstall(sAIDAppletB1st)
                .close()
            )
            // Select applet A
            .append(apduSelectAppletA, responseOK)
            // Verify all memory returned
            .append(new CommandAPDU(0x80, 0x18, 0x00, 0x00, 0x7F), responseOK)
            // AM session
            .append(
                // Select SD & open secure channel
                ams.openSession(sAID_ISD)
                // Create applet B's first instance again for testing package deletion later on
                .install(sAIDPackageB, sAIDAppletB, sAIDAppletB1st)
                // Try to delete package B including instances (success expected)
                .unload(sAIDPackageB, true)
                // Try to delete package C (success expected)
                .unload(sAIDPackageLibC)
                // Try to delete package A including instances (success expected)
                .unload(sAIDPackageA, true)
                .close());

        // Run script without expecting any errors
        List<ResponseAPDU> responses = script.run(card.getBasicChannel());
        System.out.println("Responses count: " + responses.size());
    }

    /**
     * Get single argument passed via command line
     *
     * @param args All arguments given
     * @param argName Argument to fetch
     * @param sDefault Default in case argument was not found
     * @return Argument found
     */
    private static String getArg(String[] args, String argName, String sDefault) throws IllegalArgumentException {

        String value = sDefault;

        for (String param : args) {
            if (param.startsWith("-" + argName + "=")) {
                value = param.substring(param.indexOf('=') + 1);
            }
        }

        if(value == null || value.length() == 0) {
            throw new IllegalArgumentException("Mandatory argument [" + argName + "] is missing");
        }
        return value;
    }

    /**
     * Puts all ATR bytes into a single string using hexadecimal format
     * @param ATR ATR bytes
     * @return Formatted ATR
     */
    private static String getFormattedATR(byte[] ATR) {
        StringBuilder sb = new StringBuilder();
        for (byte b : ATR) {
            sb.append(String.format("%02X ", b));
        }
        return String.format("ATR: [%s]", sb.toString().trim());
    }

    /**
     * Obtain card terminal
     *
     * @param connectionParams
     * @return
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws CardException
     */
    private static CardTerminal getTerminal(String... connectionParams) throws NoSuchAlgorithmException, NoSuchProviderException, CardException {

        TerminalFactory tf;
        CardTerminal ct = null;
        String connectivityType = connectionParams[0];
        if (connectivityType.equals("socket")) {
            String ipaddr = connectionParams[1];
            String port = connectionParams[2];
            tf = TerminalFactory.getInstance("SocketCardTerminalFactoryType",
                    List.of(new InetSocketAddress(ipaddr, Integer.parseInt(port))),
                    "SocketCardTerminalProvider");
            ct = tf.terminals().list().get(0);
        }
        else if (connectivityType.equals("pcsc")) {
            tf = TerminalFactory.getDefault();
            for (CardTerminal terminal : tf.terminals().list()) {
                if (terminal.getName().equals(connectionParams[1])) {
                    ct = terminal;
                    break;
                }
            }
        }
        return ct;
    }

    /**
     * Extension of APDUScript allowing to accept a ResonseAPDU with expected SW (e. g. when errors should be tested)
     */
    private static class TestScript extends APDUScript {
        private List<CommandAPDU>  commands = new LinkedList<>();
        private List<ResponseAPDU> responses = new LinkedList<>();
        private int index = 0;

        @Override
        public List<ResponseAPDU> run(CardChannel channel) throws ScriptFailedException {
            return super.run(channel, c -> lookupIndex(c), r -> !isExpected(r));
        }

        @Override
        public TestScript append(Scriptable<CardChannel, CommandAPDU, ResponseAPDU> other) {
            super.append(other);
            return this;
        }

        public TestScript append(CommandAPDU apdu, ResponseAPDU expected) {
            super.append(apdu);
            this.commands.add(apdu);
            this.responses.add(expected);
            return this;
        }

        @Override
        public TestScript append(CommandAPDU apdu) {
            super.append(apdu);
            return this;
        }

        private CommandAPDU lookupIndex(CommandAPDU apdu) {
            print(apdu);
            this.index = IntStream.range(0, this.commands.size())
                    .filter(i -> apdu == this.commands.get(i))
                    .findFirst()
                    .orElse(-1);
            return apdu;
        }

        private boolean isExpected(ResponseAPDU response) {

            ResponseAPDU expected = (index < 0)? response : this.responses.get(index);
            if (!response.equals(expected)) {
                System.out.println("Received: ");
                print(response);
                System.out.println("Expected: ");
                print(expected);
                return false;
            }
            print(response);
            return true;
        }

        private static void print(CommandAPDU apdu) {
            StringBuilder sb = new StringBuilder();
            sb.append(String.format("%02X%02X%02X%02X %02X[", apdu.getCLA(), apdu.getINS(), apdu.getP1(), apdu.getP2(), apdu.getNc()));
            for (byte b : apdu.getData()) {
                sb.append(String.format("%02X", b));
            }
            sb.append("]");
            System.out.format("[%1$tF %1$tT %1$tL %1$tZ] [APDU-C] %2$s %n", System.currentTimeMillis(), sb.toString());
        }

        private static void print(ResponseAPDU apdu) {
            byte[] bytes = apdu.getData();
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) {
                sb.append(String.format("%02X", b));
            }
            System.out.format("[%1$tF %1$tT %1$tL %1$tZ] [APDU-R] [%2$s] SW:%3$04X %n", System.currentTimeMillis(), sb.toString(), apdu.getSW());
        }
    }
}
