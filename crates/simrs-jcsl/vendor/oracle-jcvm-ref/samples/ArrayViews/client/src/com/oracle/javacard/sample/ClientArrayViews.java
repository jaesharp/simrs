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
import com.oracle.javacard.ams.AMSession;
import com.oracle.javacard.ams.config.AID;
import com.oracle.javacard.ams.config.CAPFile;
import com.oracle.javacard.ams.script.APDUScript;
import com.oracle.javacard.ams.script.ScriptFailedException;
import com.oracle.javacard.ams.script.Scriptable;

public class ClientArrayViews {

    final static String sAID_ISD     = "aid:A000000151000000";

    // Loading/ (no installing) order: 1
    final static String sAIDPackageShareable = "aid:A00000006203010C0B";

    // Loading/Installing order: 2
    final static String sAIDPackageServer    = "aid:A00000006203010C0C";
    final static String sAIDAppletServer     = sAIDPackageServer + "02";
    final static String sAIDAppletServerInst = sAIDPackageServer + "02";

    // Loading/Installing order: 3
    final static String sAIDPackageClient    = "aid:A00000006203010C0D";
    final static String sAIDAppletClient     = sAIDPackageClient + "01";
    final static String sAIDAppletClientInst = sAIDPackageClient + "01";

    private final static ResponseAPDU responseOK = new ResponseAPDU(new byte[] { (byte)0x90, (byte)0x00 } );

    private static CAPFile appFile_Client = null;
    private static CAPFile appFile_Server = null;
    private static CAPFile appFile_Shared = null;

    private static String HOST_DEFAULT = "socket:localhost:9025";

    /**
     * Launch the sample
     *
     * @param args command line arguments.<br>
     * Use {@code
     * -capClient=<.../ClientApplet.cap>
     * -capServer=<.../ServerApplet.cap>
     * -capShared=<.../MyShareable.cap>
     * -props=<property file>}
     */
    public static void main(String[] args) {

        int iResult = 0;

        try {
            // Application binaries needed for execution
            appFile_Client = CAPFile.from(getArg(args, "capClient", null));
            appFile_Server = CAPFile.from(getArg(args, "capServer", null));
            appFile_Shared = CAPFile.from(getArg(args, "capShared", null));

            // Configuration stage for connection to simulator
            Properties props   = new Properties();
            props.load(new FileInputStream(getArg(args, "props", null)));

            AMService ams = AMServiceFactory.getInstance("GP2.2");
            ams.setProperties(props);
            for (String key : ams.getPropertiesKeys()) {
                System.out.println(key + " = " + ams.getProperty(key));
            }

            // Session for deployments of necessary packages/applets (load / install stage)
            AMSession deploy =
                // Select SD & open secure channel
                ams.openSession(sAID_ISD)       // select SD & open secure channel
                    .load(sAIDPackageShareable, appFile_Shared.getBytes())
                    .load(sAIDPackageServer,    appFile_Server.getBytes())
                    .load(sAIDPackageClient,    appFile_Client.getBytes())
                    .install(sAIDPackageServer, sAIDAppletServer, sAIDAppletServerInst)
                    .install(sAIDPackageClient, sAIDAppletClient, sAIDAppletClientInst)
                    .close();

            // Session for clean-up of packages/applets used in example (uninstall/unload stage)
            AMSession undeploy =
                // Select SD & open secure channel
                ams.openSession(sAID_ISD).
                    uninstall(sAIDAppletClientInst).
                    uninstall(sAIDAppletServerInst).
                    unload(sAIDPackageClient).
                    unload(sAIDPackageServer).
                    unload(sAIDPackageShareable).
                    close();

            TestScript testScript = new TestScript()

                // AM Session preparation
                .append(deploy)
                // Select applet A
                .append(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, AID.from(sAIDAppletClient).toBytes(), 0x7F),
                        responseOK)
                // Any APDU starts the client
                .append(new CommandAPDU(0x80, 0x10, 0x01, 0x02, new byte[] {0x01, 0x02, 0x03, 0x04, 0x05}, 0x7F),
                        responseOK)
                // AM Session clean-up
                .append(undeploy);

            // Terminal to simulator
            CardTerminal terminal = getTerminal(getArg(args, "host", HOST_DEFAULT).split(":"));

            // With a valid terminal wait some seconds to allow connections
            if (terminal != null && terminal.waitForCardPresent(10000)) {
                System.out.println("Connection to simulator established: "+ terminal.getName());
                Card card = terminal.connect("*");
                System.out.println(getFormattedATR(card.getATR().getBytes()));

                List<ResponseAPDU> responses = testScript.run(card.getBasicChannel());
                card.disconnect(true);

                System.out.println("Responses count: " + responses.size());
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

        if(value == null || (value.length() == 0)) {
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
