package com.simrs.jcardsim;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;

import javacard.framework.AID;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * Terminal-side TCP bridge for licel/jcardsim.
 *
 * <p>Wire protocol (see simrs-jcardsim/src/protocol.rs for the Rust side):
 *
 * <pre>
 *   Offset  Size  Field
 *   0       1     Command type (0x00 APDU, 0xF0 power-on, 0xFE power-off)
 *   1       1     Reserved (0x00)
 *   2       2     Payload length (big-endian uint16)
 *   4       N     Payload bytes
 * </pre>
 *
 * <p>Responses echo the command byte.
 *
 * <p>Usage:
 *
 * <pre>
 *   java -cp jcardsim-3.0.5.jar:bridge.jar com.simrs.jcardsim.Bridge \
 *     --port 9125 \
 *     --applet-class com.example.MyApplet \
 *     --applet-aid F000000001
 * </pre>
 */
public final class Bridge {

    private static final byte CMD_APDU = 0x00;
    private static final byte CMD_POWER_ON = (byte) 0xF0;
    private static final byte CMD_POWER_OFF = (byte) 0xFE;

    private Bridge() {}

    public static void main(String[] args) throws Exception {
        Args parsed = Args.parse(args);

        CardSimulator simulator = new CardSimulator();
        AID aid = AIDUtil.create(parsed.appletAidHex);
        Class<?> appletClass = Class.forName(parsed.appletClass);
        @SuppressWarnings("unchecked")
        Class<? extends javacard.framework.Applet> typed =
                (Class<? extends javacard.framework.Applet>) appletClass;
        simulator.installApplet(aid, typed);

        try (ServerSocket server = new ServerSocket(parsed.port)) {
            server.setSoTimeout(0);
            // Emit readiness on stdout so the Rust launcher can skip
            // polling if it wants to.
            System.out.println("LISTENING " + parsed.port);
            System.out.flush();

            // Single-client: jcardsim state is per-process, not per-conn.
            try (Socket client = server.accept()) {
                serve(simulator, aid, client);
            }
        }
    }

    private static void serve(CardSimulator simulator, AID aid, Socket client) throws IOException {
        DataInputStream in = new DataInputStream(client.getInputStream());
        DataOutputStream out = new DataOutputStream(client.getOutputStream());

        while (true) {
            int cmdType;
            try {
                cmdType = in.readUnsignedByte();
            } catch (java.io.EOFException eof) {
                return; // client hung up
            }
            in.readUnsignedByte();                      // reserved
            int len = in.readUnsignedShort();           // big-endian
            byte[] payload = new byte[len];
            in.readFully(payload);

            byte[] rsp;
            switch (cmdType) {
                case CMD_APDU:
                    rsp = apdu(simulator, aid, payload);
                    writeFrame(out, CMD_APDU, rsp);
                    break;
                case CMD_POWER_ON:
                    rsp = powerOn(simulator, aid);
                    writeFrame(out, CMD_POWER_ON, rsp);
                    break;
                case CMD_POWER_OFF:
                    simulator.reset();
                    writeFrame(out, CMD_POWER_OFF, new byte[0]);
                    break;
                default:
                    // Unknown command: echo an empty frame with the
                    // same cmd byte; the Rust side treats anything it
                    // didn't send as an InvalidMessage.
                    writeFrame(out, (byte) cmdType, new byte[0]);
                    break;
            }
        }
    }

    private static byte[] apdu(CardSimulator simulator, AID aid, byte[] cmd) {
        CommandAPDU capdu = new CommandAPDU(cmd);
        ResponseAPDU rapdu = simulator.transmitCommand(capdu);
        return rapdu.getBytes();
    }

    private static byte[] powerOn(CardSimulator simulator, AID aid) {
        byte[] atr = simulator.getATR();
        // Select the installed applet so subsequent APDUs land there
        // without the caller having to send a SELECT first.
        simulator.selectApplet(aid);
        return atr != null ? atr : new byte[0];
    }

    private static void writeFrame(DataOutputStream out, byte cmdType, byte[] payload)
            throws IOException {
        if (payload.length > 0xFFFF) {
            throw new IOException("payload too large: " + payload.length);
        }
        out.writeByte(cmdType);
        out.writeByte(0x00);
        out.writeShort(payload.length);
        out.write(payload);
        out.flush();
    }

    /** Minimal CLI-arg parser -- no external dep. */
    private static final class Args {
        int port = 9125;
        String appletClass;
        String appletAidHex;

        static Args parse(String[] argv) {
            Args a = new Args();
            for (int i = 0; i < argv.length; i++) {
                switch (argv[i]) {
                    case "--port":
                        a.port = Integer.parseInt(argv[++i]);
                        break;
                    case "--applet-class":
                        a.appletClass = argv[++i];
                        break;
                    case "--applet-aid":
                        a.appletAidHex = argv[++i];
                        break;
                    default:
                        throw new IllegalArgumentException("unknown argument: " + argv[i]);
                }
            }
            if (a.appletClass == null || a.appletAidHex == null) {
                throw new IllegalArgumentException(
                        "usage: --port <n> --applet-class <FQCN> --applet-aid <hex>");
            }
            return a;
        }
    }
}
