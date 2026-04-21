package com.simrs.jcardengine;

import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.utils.AIDUtil;

import javacard.framework.AID;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * Terminal-side TCP bridge for martinpaljak/JCardEngine.
 *
 * <p>Wire protocol (see crates/simrs-jcardengine/src/protocol.rs for
 * the Rust side):
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
 * <p>Stdout protocol: prints {@code LISTENING <port>\n} immediately
 * after {@code ServerSocket} bind and before {@code accept()}, so the
 * Rust launcher treats the socket as accept-ready. Stderr carries any
 * uncaught exception stack trace -- the Rust launcher drains stderr
 * on a background thread and includes the tail in failure messages.
 *
 * <p>Usage:
 *
 * <pre>
 *   java -cp jcardengine-26.04.06.jar:bridge.jar com.simrs.jcardengine.Bridge \
 *     --port 9225 \
 *     --applet-class com.simrs.jcardengine.HelloWorldApplet \
 *     --applet-aid F000000001
 * </pre>
 */
public final class Bridge {

    private static final byte CMD_APDU = 0x00;
    private static final byte CMD_POWER_ON = (byte) 0xF0;
    private static final byte CMD_POWER_OFF = (byte) 0xFE;

    private Bridge() {}

    public static void main(String[] args) {
        try {
            runOrThrow(args);
        } catch (Throwable t) {
            // Print the full stack trace to stderr, flush it, and exit
            // non-zero. The Rust launcher drains stderr on a background
            // thread, so the caller surface error includes this trace.
            PrintStream err = System.err;
            err.println("jcardengine bridge fatal error:");
            t.printStackTrace(err);
            err.flush();
            System.exit(1);
        }
    }

    private static void runOrThrow(String[] args) throws Exception {
        Args parsed = Args.parse(args);

        Simulator simulator = new Simulator();
        AID aid = AIDUtil.create(parsed.appletAidHex);
        Class<?> appletClass = Class.forName(parsed.appletClass);
        @SuppressWarnings("unchecked")
        Class<? extends javacard.framework.Applet> typed =
                (Class<? extends javacard.framework.Applet>) appletClass;
        // Install with empty install params. 2-arg overload resolves to
        // the JavaCardEngine default method which delegates to the
        // 3-arg form with an empty byte array.
        simulator.installApplet(aid, typed);

        try (ServerSocket server = new ServerSocket(parsed.port)) {
            server.setSoTimeout(0);
            // Signal readiness *before* blocking in accept(). The Rust
            // launcher scans stdout for this line, so the order matters.
            System.out.println("LISTENING " + parsed.port);
            System.out.flush();

            // Single-client: simulator state is per-process, not
            // per-connection. A second connect would step on the first.
            try (Socket client = server.accept()) {
                serve(simulator, aid, client);
            }
        }
    }

    private static void serve(Simulator simulator, AID aid, Socket client) throws IOException {
        DataInputStream in = new DataInputStream(client.getInputStream());
        DataOutputStream out = new DataOutputStream(client.getOutputStream());

        while (true) {
            int cmdType;
            try {
                cmdType = in.readUnsignedByte();
            } catch (java.io.EOFException eof) {
                return; // client hung up cleanly
            }
            in.readUnsignedByte();            // reserved byte
            int len = in.readUnsignedShort(); // big-endian payload length
            byte[] payload = new byte[len];
            in.readFully(payload);

            byte[] rsp;
            switch (cmdType) {
                case CMD_APDU:
                    rsp = simulator.transceive(payload);
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
                    // same cmd byte. The Rust client treats any tag it
                    // didn't send as an InvalidMessage.
                    writeFrame(out, (byte) cmdType, new byte[0]);
                    break;
            }
        }
    }

    private static byte[] powerOn(Simulator simulator, AID aid) {
        simulator.reset();
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
        int port = 9225;
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
