/*
 * Copyright (c) 1998, 2025, Oracle and/or its affiliates. All rights reserved.
 */

package com.oracle.javacard.sample;

import java.io.IOException;
import java.io.FileInputStream;
import java.security.NoSuchProviderException;
import java.util.List;
import java.util.Properties;
import java.util.LinkedList;
import java.net.InetSocketAddress;

import java.security.NoSuchAlgorithmException;
import java.util.stream.IntStream;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

import com.oracle.javacard.ams.script.APDUScript;
import com.oracle.javacard.ams.script.ScriptFailedException;
import com.oracle.javacard.ams.script.Scriptable;
import com.oracle.javacard.ams.AMSession;
import com.oracle.javacard.ams.config.AID;
import com.oracle.javacard.ams.config.CAPFile;
import com.oracle.javacard.ams.AMService;
import com.oracle.javacard.ams.AMServiceFactory;

public class AMSSignatureMessageRecoveryClient {

	static final String isdAID = "aid:A000000151000000";
	static final String sAID_CAP = "aid:A00000006203010C0C";
	static final String sAID_AppletClass = "aid:A00000006203010C0C01";
	static final String sAID_AppletInstance = "aid:A00000006203010C0C01";
	static final CommandAPDU selectApplet = new CommandAPDU(0x00, 0xA4, 0x04, 0x00, AID.from(sAID_AppletInstance).toBytes(), 256);

	private static String HOST_DEFAULT = "socket:localhost:9025";

	/**
	 * Launch the sample
	 *
	 * @param args command arguments. Use {@code -cap=<capfile> -props=<propsfile>}
	 */
	public static void main(String[] args) {

		int iResult = 0;

		try {
			CAPFile appFile = CAPFile.from(getArg(args, "cap", null));
            Properties props = new Properties();
            props.load(new FileInputStream(getArg(args, "props", null)));

            // Create and configure Application Management Service
            AMService ams = AMServiceFactory.getInstance("GP2.2");
            ams.setProperties(props);
            for (String key : ams.getPropertiesKeys()) {
                System.out.println(key + " = " + ams.getProperty(key));
            }

            // Application Management session used to deploy CAPFile
            AMSession deploy = ams.openSession(isdAID)   // select SD & open secure channel
                    .load(sAID_CAP, appFile.getBytes())  // load an application file
                    .install(sAID_CAP,                   // install application
                            sAID_AppletClass, sAID_AppletInstance)
                    .close();

            // Application Management session used to undeploy CAPFile
            AMSession undeploy = ams.openSession(isdAID) // select SD & open secure channel
                    .uninstall(sAID_AppletInstance)      // uninstall the application
                    .unload(sAID_CAP)                    // unload the application code
                    .close();

			// sample script: deploy an Applet, use it and undeploy it.
	        TestScript testScript = new TestScript()
	        		.append( deploy )
                    .append( selectApplet )

					// sigMsgPartRec
					// send data 70 bytes
					.append(new CommandAPDU(0x80, 0x10, 0x00, 0x00,
							new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
									0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
									0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
									0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
									0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45,
									0x46 },
							256),
							new ResponseAPDU(new byte[] { 0x2d, 0x15, 0x79, (byte) 0x89, (byte) 0xba, 0x71, 0x6d, 0x31,
									0x6c, 0x0e, 0x29, 0x55, (byte) 0xc0, 0x0e, (byte) 0x80, (byte) 0xc3, 0x5c,
									(byte) 0xa3, (byte) 0xe8, (byte) 0xa1, 0x12, 0x65, (byte) 0xe3, 0x6f, (byte) 0xb2,
									0x51, 0x44, 0x7d, 0x30, 0x4a, 0x24, (byte) 0xcf, (byte) 0xa1, 0x1b, (byte) 0xaa,
									0x30, 0x48, (byte) 0xd3, 0x70, 0x4a, 0x0b, (byte) 0xe7, (byte) 0x9a, 0x05, 0x1f,
									0x5f, (byte) 0x87, (byte) 0xc7, (byte) 0x8f, (byte) 0xe4, (byte) 0xae, (byte) 0xbc,
									(byte) 0xde, 0x0a, 0x63, 0x6a, 0x28, 0x48, 0x52, (byte) 0xc0, (byte) 0xe7,
									(byte) 0xd2, 0x7f, (byte) 0xfe, 0x00, 0x2a, (byte) 0x90, 0x00 })) // Signature data
																										// expected.
																										// Last two
																										// bytes is the
																										// size of
																										// recoverable
																										// data.
																										// Expected 42
																										// bytes

					// verify stage. send in signature
					.append(new CommandAPDU(0x80, 0x12, 0x00, 0x00,
							new byte[] { 0x2d, 0x15, 0x79, (byte) 0x89, (byte) 0xba, 0x71, 0x6d, 0x31, 0x6c, 0x0e, 0x29,
									0x55, (byte) 0xc0, 0x0e, (byte) 0x80, (byte) 0xc3, 0x5c, (byte) 0xa3, (byte) 0xe8,
									(byte) 0xa1, 0x12, 0x65, (byte) 0xe3, 0x6f, (byte) 0xb2, 0x51, 0x44, 0x7d, 0x30,
									0x4a, 0x24, (byte) 0xcf, (byte) 0xa1, 0x1b, (byte) 0xaa, 0x30, 0x48, (byte) 0xd3,
									0x70, 0x4a, 0x0b, (byte) 0xe7, (byte) 0x9a, 0x05, 0x1f, 0x5f, (byte) 0x87,
									(byte) 0xc7, (byte) 0x8f, (byte) 0xe4, (byte) 0xae, (byte) 0xbc, (byte) 0xde, 0x0a,
									0x63, 0x6a, 0x28, 0x48, 0x52, (byte) 0xc0, (byte) 0xe7, (byte) 0xd2, 0x7f,
									(byte) 0xfe },
							256), new ResponseAPDU(new byte[] { 0x00, 0x2a, (byte) 0x90, 0x00 }))

					// complete signature verification by sending in non-recoverable part of message
					.append(new CommandAPDU(0x80, 0x12, 0x00, 0x00,
							new byte[] { 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
									0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45,
									0x46 }), new ResponseAPDU(new byte[] { (byte) 0x90, 0x00 }))

					// sigMsgFullRec
					// Sign expected the actual data
					.append(new CommandAPDU(0x80, 0x10, 0x00, 0x00, new byte[] { 0x01 }, 256),
							new ResponseAPDU(new byte[] { (byte) 0xa3, 0x49, 0x1d, 0x51, 0x55, 0x05, 0x49, 0x71,
									(byte) 0xba, (byte) 0xdc, 0x77, 0x22, (byte) 0xce, (byte) 0x9a, 0x51, 0x71,
									(byte) 0xf8, (byte) 0xb1, (byte) 0x88, (byte) 0x8d, 0x55, 0x05, (byte) 0xd5, 0x2b,
									(byte) 0xae, (byte) 0xf6, (byte) 0xb7, 0x04, (byte) 0xd9, 0x1d, 0x09, 0x35, 0x17,
									(byte) 0xec, 0x73, 0x11, (byte) 0xd5, 0x7f, (byte) 0xfd, (byte) 0xeb, (byte) 0xb3,
									(byte) 0xd9, (byte) 0x98, 0x45, (byte) 0xf7, (byte) 0x8a, (byte) 0xb6, 0x72, 0x21,
									0x44, (byte) 0xa1, 0x32, (byte) 0xb3, (byte) 0xa1, (byte) 0xce, 0x72, (byte) 0xc5,
									0x6d, (byte) 0xcc, (byte) 0xee, 0x18, 0x64, 0x2e, 0x76, 0x00, 0x01, (byte) 0x90, 0x00 }))

					.append(new CommandAPDU(0x80, 0x11, 0x00, 0x00,
							new byte[] { (byte) 0xa3, 0x49, 0x1d, 0x51, 0x55, 0x05, 0x49, 0x71, (byte) 0xba,
									(byte) 0xdc, 0x77, 0x22, (byte) 0xce, (byte) 0x9a, 0x51, 0x71, (byte) 0xf8,
									(byte) 0xb1, (byte) 0x88, (byte) 0x8d, 0x55, 0x05, (byte) 0xd5, 0x2b, (byte) 0xae,
									(byte) 0xf6, (byte) 0xb7, 0x04, (byte) 0xd9, 0x1d, 0x09, 0x35, 0x17, (byte) 0xec,
									0x73, 0x11, (byte) 0xd5, 0x7f, (byte) 0xfd, (byte) 0xeb, (byte) 0xb3, (byte) 0xd9,
									(byte) 0x98, 0x45, (byte) 0xf7, (byte) 0x8a, (byte) 0xb6, 0x72, 0x21, 0x44,
									(byte) 0xa1, 0x32, (byte) 0xb3, (byte) 0xa1, (byte) 0xce, 0x72, (byte) 0xc5, 0x6d,
									(byte) 0xcc, (byte) 0xee, 0x18, 0x64, 0x2e, 0x76 },
							256), new ResponseAPDU(new byte[] { (byte) 0x90, 0x00 }))

					.append(undeploy);

			// Terminal to simulator
			CardTerminal t = getTerminal(getArg(args, "host", HOST_DEFAULT).split(":"));

			// With a valid terminal wait some seconds to allow connections
			if (t != null && t.waitForCardPresent(10000)) {
				System.out.println("Connection to simulator established: "+ t.getName());
				Card c = t.connect("*");
				System.out.println(getFormattedATR(c.getATR().getBytes()));

				List<ResponseAPDU> responses = testScript.run(c.getBasicChannel());
				c.disconnect(true);

				System.out.println("Responses count: " + responses.size());
			}
			else {
				System.out.println("Connection to simulator failed");
				iResult = -1;
			}

		} catch (NoSuchAlgorithmException | NoSuchProviderException | CardException | ScriptFailedException | IOException e) {
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

	private static class TestScript extends APDUScript {
        private List<CommandAPDU>  commands = new LinkedList<>();
        private List<ResponseAPDU> responses = new LinkedList<>();
        private int index = 0;

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
