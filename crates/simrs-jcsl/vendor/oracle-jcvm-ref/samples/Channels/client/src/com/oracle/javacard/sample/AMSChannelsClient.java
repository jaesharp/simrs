/*
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

public class AMSChannelsClient {

	static final String isdAID = "aid:A000000151000000";
	static final String sAID_CAP = "aid:A00000006203010C0B";
	static final String sAID_AppletClass_AA = "aid:A00000006203010C0B01";
	static final String sAID_AppletInstance_AA = "aid:A00000006203010C0B01";
	static final String sAID_AppletClass_CM = "aid:A00000006203010C0B02";
	static final String sAID_AppletInstance_CM = "aid:A00000006203010C0B02";
	static final CommandAPDU selectApplet_AA = new CommandAPDU(0x00, 0xA4, 0x04, 0x00, AID.from(sAID_AppletClass_AA).toBytes(), 256);
	static final CommandAPDU selectApplet_CM = new CommandAPDU(0x00, 0xA4, 0x04, 0x00, AID.from(sAID_AppletClass_CM).toBytes(), 256);

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
							sAID_AppletClass_AA, sAID_AppletInstance_AA, new byte[] { 0x01, (byte) 0x98, 0x00, 0x01, 0x00, 0x05 })
					.install(sAID_CAP, 					 // install application
							sAID_AppletClass_CM, sAID_AppletInstance_CM)
					.close();

			// Application Management session used to undeploy CAPFile
			AMSession undeploy = ams.openSession(isdAID) // select SD & open secure channel
					.unload(sAID_CAP, true)              // unload the application code
					.close();

			// sample script: deploy an Applet, use it and undeploy it.
			TestScript testScript = new TestScript()

					.append( deploy )
					.append( selectApplet_AA )

					// Initialize Account accessor with 100 credits
					.append(new CommandAPDU(0x80, 0x20, 0x00, 0x00, new byte[] { 0x00, 0x64}),
							new ResponseAPDU(new byte[] { (byte)0x90, (byte)0x00}))

					// Assume some time happens, and the user turns the device on to use it...
					// Terminal selects Connection Manager upon turning on the device
					.append(selectApplet_CM)

					.append(new CommandAPDU((byte) 0x80, (byte) 0x40, (byte) 0x00, (byte) 0x00, new byte[] {
							(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06,
							(byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C, (byte) 0x0D,
							(byte) 0x0E, (byte) 0x0F, (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13, (byte) 0x14,
							(byte) 0x15, (byte) 0x16, (byte) 0x17, (byte) 0x18, (byte) 0x19, (byte) 0x1A, (byte) 0x1B,
							(byte) 0x1C, (byte) 0x1D, (byte) 0x1E, (byte) 0x1F, (byte) 0x20, (byte) 0x21, (byte) 0x22,
							(byte) 0x23, (byte) 0x24, (byte) 0x25, (byte) 0x26, (byte) 0x27, (byte) 0x28, (byte) 0x29,
							(byte) 0x2A, (byte) 0x2B, (byte) 0x2C, (byte) 0x2D, (byte) 0x2E, (byte) 0x2F, (byte) 0x30,
							(byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34, (byte) 0x35, (byte) 0x36, (byte) 0x37,
							(byte) 0x38, (byte) 0x39, (byte) 0x3A, (byte) 0x3B, (byte) 0x3C, (byte) 0x3D, (byte) 0x3E,
							(byte) 0x3F, (byte) 0x40, (byte) 0x41, (byte) 0x42, (byte) 0x43, (byte) 0x44, (byte) 0x45,
							(byte) 0x46, (byte) 0x47, (byte) 0x48, (byte) 0x49, (byte) 0x4A, (byte) 0x4B, (byte) 0x4C,
							(byte) 0x4D, (byte) 0x4E, (byte) 0x4F, (byte) 0x50, (byte) 0x51, (byte) 0x52, (byte) 0x53,
							(byte) 0x54, (byte) 0x55, (byte) 0x56, (byte) 0x57, (byte) 0x58, (byte) 0x59, (byte) 0x5A,
							(byte) 0x5B, (byte) 0x5C, (byte) 0x5D, (byte) 0x5E, (byte) 0x5F, (byte) 0x60, (byte) 0x61,
							(byte) 0x62, (byte) 0x63, (byte) 0x64, (byte) 0x65, (byte) 0x66, (byte) 0x67, (byte) 0x68,
							(byte) 0x69, (byte) 0x6A, (byte) 0x6B, (byte) 0x6C, (byte) 0x6D, (byte) 0x6E, (byte) 0x6F,
							(byte) 0x70, (byte) 0x71, (byte) 0x72, (byte) 0x73, (byte) 0x74, (byte) 0x75, (byte) 0x76,
							(byte) 0x77, (byte) 0x78, (byte) 0x79, (byte) 0x7A, (byte) 0x7B, (byte) 0x7C, (byte) 0x7D,
							(byte) 0x7E, (byte) 0x7F, (byte) 0x80, (byte) 0x81, (byte) 0x82, (byte) 0x83, (byte) 0x84,
							(byte) 0x85, (byte) 0x86, (byte) 0x87, (byte) 0x88, (byte) 0x89, (byte) 0x8A, (byte) 0x8B,
							(byte) 0x8C, (byte) 0x8D, (byte) 0x8E, (byte) 0x8F, (byte) 0x90, (byte) 0x91, (byte) 0x92,
							(byte) 0x93, (byte) 0x94, (byte) 0x95, (byte) 0x96, (byte) 0x97, (byte) 0x98, (byte) 0x99,
							(byte) 0x9A, (byte) 0x9B, (byte) 0x9C, (byte) 0x9D, (byte) 0x9E, (byte) 0x9F, (byte) 0xA0,
							(byte) 0xA1, (byte) 0xA2, (byte) 0xA3, (byte) 0xA4, (byte) 0xA5, (byte) 0xA6, (byte) 0xA7,
							(byte) 0xA8, (byte) 0xA9, (byte) 0xAA, (byte) 0xAB, (byte) 0xAC, (byte) 0xAD, (byte) 0xAE,
							(byte) 0xAF, (byte) 0xB0, (byte) 0xB1, (byte) 0xB2, (byte) 0xB3, (byte) 0xB4, (byte) 0xB5,
							(byte) 0xB6, (byte) 0xB7, (byte) 0xB8, (byte) 0xB9, (byte) 0xBA, (byte) 0xBB, (byte) 0xBC,
							(byte) 0xBD, (byte) 0xBE, (byte) 0xBF, (byte) 0xC0, (byte) 0xC1, (byte) 0xC2, (byte) 0xC3,
							(byte) 0xC4, (byte) 0xC5, (byte) 0xC6, (byte) 0xC7, (byte) 0xC8, (byte) 0xC9, (byte) 0xCA,
							(byte) 0xCB, (byte) 0xCC, (byte) 0xCD, (byte) 0xCE, (byte) 0xCF, (byte) 0xD0, (byte) 0xD1,
							(byte) 0xD2, (byte) 0xD3, (byte) 0xD4, (byte) 0xD5, (byte) 0xD6, (byte) 0xD7, (byte) 0xD8,
							(byte) 0xD9, (byte) 0xDA, (byte) 0xDB, (byte) 0xDC, (byte) 0xDD, (byte) 0xDE, (byte) 0xDF,
							(byte) 0xE0, (byte) 0xE1, (byte) 0xE2, (byte) 0xE3, (byte) 0xE4, (byte) 0xE5, (byte) 0xE6,
							(byte) 0xE7, (byte) 0xE8, (byte) 0xE9, (byte) 0xEA, (byte) 0xEB, (byte) 0xEC, (byte) 0xED,
							(byte) 0xEE, (byte) 0xEF, (byte) 0xF0, (byte) 0xF1, (byte) 0xF2, (byte) 0xF3, (byte) 0xF4,
							(byte) 0xF5, (byte) 0xF6, (byte) 0xF7, (byte) 0xF8, (byte) 0xF9, (byte) 0xFA, (byte) 0xFB,
							(byte) 0xFC, (byte) 0xFD, (byte) 0xFE, (byte) 0xFF, (byte) 0x00, (byte) 0x01, (byte) 0x02,
							(byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x09,
							(byte) 0x0A, (byte) 0x0B, (byte) 0x0C, (byte) 0x0D, (byte) 0x0E, (byte) 0x0F, (byte) 0x10,
							(byte) 0x11, (byte) 0x12, (byte) 0x13, (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17,
							(byte) 0x18, (byte) 0x19, (byte) 0x1A, (byte) 0x1B, (byte) 0x1C, (byte) 0x1D, (byte) 0x1E,
							(byte) 0x1F }, 288),
							new ResponseAPDU(
									new byte[] { (byte) 0x90, (byte) 0x00 }))

					// Upon network carrier detect, terminal decodes area code (408 dec)
					// and sends a "Time tick" to the card
					.append(new CommandAPDU(0x80, 0x10, 0x00, 0x00, new byte[] {0x01, (byte) 0x98}),
							new ResponseAPDU(new byte[] { (byte)0x90, (byte)0x00}));


			// Terminal to simulator
			CardTerminal t = getTerminal(getArg(args, "host", HOST_DEFAULT).split(":"));

			// With a valid terminal wait some seconds to allow connections
			if (t != null && t.waitForCardPresent(10000)) {
				System.out.println("Connection to simulator established: "+ t.getName());
				Card c = t.connect("*");
				System.out.println(getFormattedATR(c.getATR().getBytes()));

				final CardChannel basicChannel = c.getBasicChannel();
				List<ResponseAPDU> responses = testScript.run(basicChannel);

				// The user starts using the device.  The terminal queries for available credits.
				// First, open a new logical channel, via MANAGE CHANNEL OPENcommand.
				CardChannel channel1 = c.openLogicalChannel();

				TestScript testScriptMultiChannel = new TestScript()
					.append(new CommandAPDU(getCLAChannel((byte) 0x00, channel1.getChannelNumber()), 0xA4, 0x04, 0x00,
							AID.from(sAID_AppletClass_AA).toBytes(), 256),
							new ResponseAPDU(new byte[] { (byte) 0x90, 0x00 }), channel1)

					// Terminal queries balance on user account.
					.append(new CommandAPDU(new byte[] { getCLAChannel((byte) 0x80, channel1.getChannelNumber()), 0x10,
							0x00, 0x00, 0x00 }), new ResponseAPDU(new byte[] { 0x00, 0x64, (byte) 0x90, 0x00 }),
							channel1)

					// User starts a network service.  For this, sufficient credits shall be available
					// on the user account to pay for the first time unit of device use.
					.append(new CommandAPDU(new byte[] { getCLAChannel((byte) 0x80, basicChannel.getChannelNumber()),
							0x20, 0x00, 0x00, 0x00 }), new ResponseAPDU(new byte[] { (byte) 0x90, 0x00 }), basicChannel)

					// Service initiation has a charge of one time unit.  Verified by obtaining balance.
					.append(new CommandAPDU(new byte[] { getCLAChannel((byte) 0x80, channel1.getChannelNumber()), 0x10,
							0x00, 0x00, 0x00 }), new ResponseAPDU(new byte[] { 0x00, 0x63, (byte) 0x90, 0x00 }),
							channel1)

					// Time tick for another time unit
					.append(new CommandAPDU(new byte[] { getCLAChannel((byte) 0x80, basicChannel.getChannelNumber()),
							0x10, 0x00, 0x00, 0x02, 0x01, (byte) 0x98 }),
							new ResponseAPDU(new byte[] { (byte) 0x90, 0x00 }), basicChannel)

					// Terminal queries balance.
					.append(new CommandAPDU(new byte[] { getCLAChannel((byte) 0x80, channel1.getChannelNumber()), 0x10,
							0x00, 0x00, 0x00 }), new ResponseAPDU(new byte[] { 0x00, 0x62, (byte) 0x90, 0x00 }),
							channel1)

					// Time tick.  The user has moved to a new area code (650).
					.append(new CommandAPDU(new byte[] { getCLAChannel((byte) 0x80, basicChannel.getChannelNumber()),
							0x10, 0x00, 0x00, 0x02, 0x02, (byte) 0x8A }),
							new ResponseAPDU(new byte[] { (byte) 0x90, 0x00 }), basicChannel)

					// Terminal queries balance.
					.append(new CommandAPDU(new byte[] { getCLAChannel((byte) 0x80, channel1.getChannelNumber()), 0x10,
							0x00, 0x00, 0x00 }), new ResponseAPDU(new byte[] { 0x00, 0x5D, (byte) 0x90, 0x00 }),
							channel1)

					// Time tick.  Area code (650).
					.append(new CommandAPDU(new byte[] { getCLAChannel((byte) 0x80, basicChannel.getChannelNumber()),
							0x10, 0x00, 0x00, 0x02, 0x02, (byte) 0x8A }),
							new ResponseAPDU(new byte[] { (byte) 0x90, 0x00 }), basicChannel)

					// Terminal queries balance.
					.append(new CommandAPDU(new byte[] { getCLAChannel((byte) 0x80, channel1.getChannelNumber()), 0x10,
							0x00, 0x00, 0x00 }), new ResponseAPDU(new byte[] { 0x00, 0x58, (byte) 0x90, 0x00 }),
							channel1)

					// User terminates network service. No charges applied.
					.append(new CommandAPDU(new byte[] { getCLAChannel((byte) 0x80, basicChannel.getChannelNumber()),
							0x30, 0x00, 0x00, 0x00 }), new ResponseAPDU(new byte[] { (byte) 0x90, 0x00 }), basicChannel)

					// Time tick.  Area code (650).
					.append(new CommandAPDU(new byte[] { getCLAChannel((byte) 0x80, basicChannel.getChannelNumber()),
							0x10, 0x00, 0x00, 0x02, 0x02, (byte) 0x8A }),
							new ResponseAPDU(new byte[] { (byte) 0x90, 0x00 }), basicChannel)

					// Terminal queries balance. No change, since device is not in use.
					.append(new CommandAPDU(new byte[] { getCLAChannel((byte) 0x80, channel1.getChannelNumber()), 0x10,
							0x00, 0x00, 0x00 }), new ResponseAPDU(new byte[] { 0x00, 0x58, (byte) 0x90, 0x00 }),
							channel1);

				final List<ResponseAPDU> multiChannelResponses = testScriptMultiChannel.run();
				channel1.close();

				TestScript testScriptCleanUp = new TestScript().append( undeploy );
				final List<ResponseAPDU> cleanUpResponses = testScriptCleanUp.run(basicChannel);

				c.disconnect(true);

				System.out.println("Responses count: " + (responses.size() + multiChannelResponses.size() + cleanUpResponses.size()));
			}
			else {
				System.out.println("Connection to simulator failed");
				iResult = -1;
			}

		} catch (NoSuchAlgorithmException | NoSuchProviderException | CardException | ScriptFailedException | IOException | IllegalArgumentException e) {
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

	private static byte getCLAChannel(byte cla, int channelNr) throws IllegalArgumentException {
		if (channelNr <= 3) {
			// mask of bits 7, 1, 0 (channel number)
			// 0xbc == 1011 1100
			cla &= (byte) 0xbc;
			cla |= (byte) channelNr;
		} else if (channelNr <= 19) {
			// mask of bits 7, 3, 2, 1, 0 (channel number)
			// 0xbc == 1011 0000
			cla &= (byte) 0xb0;
			cla |= (byte) 0x40;
			cla |= (byte) (channelNr - 4);
		} else {
			throw new IllegalArgumentException("Unsupported channel number: " + channelNr);
		}

		return cla;
}

	private static class TestScript extends APDUScript {
		private List<CommandAPDU>  commands = new LinkedList<>();
		private List<CardChannel> channels = new LinkedList<>();
		private List<ResponseAPDU> responses = new LinkedList<>();
		private int index = 0;

		public List<ResponseAPDU> run(CardChannel channel) throws ScriptFailedException {
			return super.run(channel, c -> lookupIndex(c), r -> !isExpected(r));
		}

		// Run on selected channel
		public List<ResponseAPDU> run() throws CardException {
			List<ResponseAPDU> res = new LinkedList<ResponseAPDU>();
			for (CommandAPDU command : commands) {
				lookupIndex(command);
				final CardChannel cardChannel = this.channels.get(index);
				if (cardChannel != null) {
					final ResponseAPDU response = cardChannel.transmit(command);
					res.add(response);
					if (!isExpected(response)) {
						throw new ScriptFailedException();
					}
				}
			}
			return res;
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

		public TestScript append(CommandAPDU apdu, ResponseAPDU expected, CardChannel channel) {
			super.append(apdu);
			this.commands.add(apdu);
			this.channels.add(channel);
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
