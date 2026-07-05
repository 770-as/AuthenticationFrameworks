package loginhook;

import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

// LoginDumpHook is the runtime callback the agent injects at the very start of
// xi.ds(int[] key, int start, int end, int marker). It reads the client's
// output buffer (field xi.al) in plaintext before the XTEA scramble runs and
// prints the full login frame as hex.
//
// This class is appended to the bootstrap classloader search so the injected
// call inside xi resolves regardless of which classloader loaded the client.
public final class LoginDumpHook {

    private static final Path AGENT_LOG =
            Paths.get(System.getProperty("user.home"), "login_dump_agent.log");

    private LoginDumpHook() {
    }

    private static void log(String msg) {
        try {
            System.out.println(msg);
            Files.write(AGENT_LOG, (msg + System.lineSeparator()).getBytes(),
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (Throwable ignored) {
        }
    }

    private static int realPos(int au) {
        return (int) ((au * -661977895L) & 0xFFFFFFFFL);
    }

    private static int realPosModern(int ab) {
        return (int) ((ab * 769523041L) & 0xFFFFFFFFL);
    }

    private static int decodeEnd(int endArg, int bufLen) {
        if (endArg > 0 && endArg <= bufLen) {
            return endArg;
        }
        int rp = realPos(endArg);
        if (rp > 0 && rp <= bufLen) {
            return rp;
        }
        rp = realPosModern(endArg);
        if (rp > 0 && rp <= bufLen) {
            return rp;
        }
        return bufLen;
    }

    private static volatile int dsCalls;

    // findByteArrays returns all non-null byte[] fields of obj across its class
    // hierarchy, since the client's obfuscated buffer field name varies by build.
    private static java.util.List<Field> byteArrayFields(Object obj) {
        java.util.List<Field> out = new java.util.ArrayList<>();
        for (Class<?> k = obj.getClass(); k != null && k != Object.class; k = k.getSuperclass()) {
            for (Field f : k.getDeclaredFields()) {
                if (f.getType() == byte[].class) {
                    f.setAccessible(true);
                    out.add(f);
                }
            }
        }
        return out;
    }

    // intFields returns all int instance fields across the hierarchy. Used to
    // recover the buffer write position (xi.au) by name-independent scanning,
    // since the obfuscated field name varies per client build.
    private static java.util.List<Field> intFields(Object obj) {
        java.util.List<Field> out = new java.util.ArrayList<>();
        for (Class<?> k = obj.getClass(); k != null && k != Object.class; k = k.getSuperclass()) {
            for (Field f : k.getDeclaredFields()) {
                if (f.getType() == int.class
                        && !java.lang.reflect.Modifier.isStatic(f.getModifiers())) {
                    f.setAccessible(true);
                    out.add(f);
                }
            }
        }
        return out;
    }

    private static volatile int ccCalls;

    private static Path mirrorCaptureDir() {
        String dir = System.getenv("LOGIN_CAPTURE_DIR");
        if (dir == null || dir.isEmpty()) {
            return null;
        }
        return Paths.get(dir);
    }

    private static void mirrorFile(String name, byte[] bytes, boolean append) throws java.io.IOException {
        Path dir = mirrorCaptureDir();
        if (dir == null) {
            return;
        }
        Files.createDirectories(dir);
        Files.write(dir.resolve(name), bytes,
                append ? new java.nio.file.OpenOption[]{
                        StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.APPEND
                } : new java.nio.file.OpenOption[]{
                        StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING
                });
    }

    // dumpStr is called as loginhook.LoginDumpHook.dumpStr($1) at the entry of
    // xi.cc(String, int) -- the method that writes a null-terminated string into
    // the active buffer. During login the client writes, in order:
    //   1. var1_2.pk  -> the game-session token packed into the RSA block
    //   2. username   -> empty for Jagex-account logins
    //   3. fr.gf      -> the CLIENT_TOKEN packed into the XTEA secure zone
    // Logging every string lets us see the real pk (distinct from fr.gf) without
    // reading the obfuscated byte buffer.
    public static void dumpStr(String s) {
        try {
            int call = ++ccCalls;
            String shown = (s == null) ? "<null>" : s;
            log("[CC-STRING] #" + call + " len=" + (s == null ? -1 : s.length()) + " val=" + shown);
            byte[] line = ("#" + call + " " + shown + System.lineSeparator()).getBytes();
            Path homeOut = Paths.get(System.getProperty("user.home"), "cc_strings.txt");
            Files.write(homeOut, line,
                    StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.APPEND);
            mirrorFile("cc_strings.txt", line, true);
        } catch (Throwable t) {
            log("[CC-STRING] hook error: " + t);
        }
    }

    private static volatile int dbCalls;

    // dumpRsa is called as loginhook.LoginDumpHook.dumpRsa($0) at the entry of
    // xi.db(BigInteger, BigInteger, byte) -- i.e. the RSA serialization buffer
    // right before modPow scrambles it. The plaintext lives in the byte[] field
    // whose first byte is the RSA header marker (0x01); the active length is
    // realPos(au), where au is the obfuscated write position.
    public static void dumpRsa(Object buf) {
        try {
            int call = ++dbCalls;

            byte[] rsa = null;
            String chosen = null;
            StringBuilder diag = new StringBuilder();
            for (Field f : byteArrayFields(buf)) {
                byte[] cand = (byte[]) f.get(buf);
                int len = cand == null ? -1 : cand.length;
                int first = (cand != null && cand.length > 0) ? (cand[0] & 0xff) : -1;
                diag.append(f.getName()).append("(len=").append(len)
                        .append(",first=0x").append(Integer.toHexString(first & 0xff)).append(") ");
                if (cand != null && cand.length > 0 && first == 1) {
                    rsa = cand;
                    chosen = f.getName();
                }
            }
            if (rsa == null) {
                log("[RSA-DUMP] db hook #" + call + ": no RSA byte[] (first=0x01); byte[] fields: " + diag);
                return;
            }

            // Recover the real length from whichever int field decodes (via the
            // -661977895 multiplier) to a plausible position inside the buffer.
            int n = -1;
            StringBuilder ints = new StringBuilder();
            for (Field f : intFields(buf)) {
                int v = f.getInt(buf);
                int rp = realPos(v);
                int rp2 = realPosModern(v);
                ints.append(f.getName()).append("=").append(v)
                        .append("(rp=").append(rp).append(",rp2=").append(rp2).append(") ");
                if (n <= 0 && rp > 0 && rp <= rsa.length) {
                    n = rp;
                } else if (n <= 0 && rp2 > 0 && rp2 <= rsa.length) {
                    n = rp2;
                } else if (n <= 0 && v > 0 && v <= rsa.length) {
                    n = v;
                }
            }
            if (n <= 0) {
                n = Math.min(rsa.length, 256);
            }

            log("[RSA-DUMP] db hook #" + call + ": field=" + chosen + " len=" + n
                    + " bufLen=" + rsa.length + " ints: " + ints);

            StringBuilder sb = new StringBuilder(n * 2);
            for (int i = 0; i < n; i++) {
                int b = rsa[i] & 0xff;
                sb.append(Character.forDigit(b >>> 4, 16));
                sb.append(Character.forDigit(b & 0xf, 16));
            }
            String line = "[RSA-PLAINTEXT] " + sb;
            log(line);

            byte[] rsaBytes = (line + System.lineSeparator()).getBytes();
            Path homeOut = Paths.get(System.getProperty("user.home"), "rsa_plaintext.txt");
            Files.write(homeOut, rsaBytes,
                    StandardOpenOption.CREATE, StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING);
            mirrorFile("rsa_plaintext.txt", rsaBytes, false);
            log("[RSA-DUMP] wrote " + homeOut.toAbsolutePath());
        } catch (Throwable t) {
            log("[RSA-DUMP] hook error: " + t);
        }
    }

    // dump is called as: loginhook.LoginDumpHook.dump($0, $3) where $0 is the
    // xi instance and $3 is the end position passed into xi.ds(...).
    public static void dump(Object buf, int endArg) {
        try {
            int call = ++dsCalls;

            // The buffer field name is obfuscated and differs per client build, so
            // scan every byte[] field and pick the one that looks like a login frame
            // (first byte 16 = new login, 18 = reconnect).
            byte[] al = null;
            String chosen = null;
            StringBuilder diag = new StringBuilder();
            for (Field f : byteArrayFields(buf)) {
                byte[] cand = (byte[]) f.get(buf);
                int len = cand == null ? -1 : cand.length;
                int first = (cand != null && cand.length > 0) ? (cand[0] & 0xff) : -1;
                diag.append(f.getName()).append("(len=").append(len)
                        .append(",first=0x").append(Integer.toHexString(first & 0xff)).append(") ");
                if (cand != null && cand.length > 0 && (first == 16 || first == 18)) {
                    al = cand;
                    chosen = f.getName();
                }
            }
            if (al == null) {
                log("[LOGIN-DUMP] ds hook #" + call + ": no login byte[] (endArg=" + endArg
                        + "); byte[] fields: " + diag);
                return;
            }

            int end = decodeEnd(endArg, al.length);

            int first = al[0] & 0xff;
            log("[LOGIN-DUMP] ds hook #" + call + ": field=" + chosen + " first=0x"
                    + Integer.toHexString(first) + " end=" + end + " alLen=" + al.length);

            StringBuilder sb = new StringBuilder(end * 2);
            for (int i = 0; i < end; i++) {
                int b = al[i] & 0xff;
                sb.append(Character.forDigit(b >>> 4, 16));
                sb.append(Character.forDigit(b & 0xf, 16));
            }

            String line = "[LOGIN-FRAME] " + sb;
            log(line);

            byte[] bytes = (line + System.lineSeparator()).getBytes();
            Path homeOut = Paths.get(System.getProperty("user.home"), "login_frame.txt");
            Files.write(homeOut, bytes,
                    StandardOpenOption.CREATE, StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING);
            mirrorFile("login_frame.txt", bytes, false);
            log("[LOGIN-DUMP] wrote " + homeOut.toAbsolutePath());

            // Arm one-shot socket block so the encrypted login frame never leaves
            // the client -- UNLESS LOGIN_NO_BLOCK is set, in which case we let
            // RuneLite's own login complete on the wire (to test whether a
            // completed login is what activates the game-session token server
            // side). With the block disabled, capture still works; RuneLite just
            // logs in normally and the bot must use a freshly minted pk.
            if (loginBlockDisabled()) {
                log("[LOGIN-BLOCK] disabled via login.noblock / LOGIN_NO_BLOCK; RuneLite login proceeds on the wire");
            } else {
                armLoginWireBlock(end);
            }
        } catch (Throwable t) {
            log("[LOGIN-DUMP] hook error: " + t);
        }
    }

    private static volatile boolean blockLoginWire;
    private static volatile int expectedWireLen = -1;
    private static volatile int blockedWrites;

    // loginBlockDisabled returns true when LOGIN_NO_BLOCK is set to a truthy
    // value, letting RuneLite's own login complete instead of dropping it.
    private static boolean loginBlockDisabled() {
        String v = System.getenv("LOGIN_NO_BLOCK");
        if (v == null) {
            v = System.getProperty("login.noblock");
        }
        if (v == null) {
            return false;
        }
        v = v.trim().toLowerCase();
        return v.equals("1") || v.equals("true") || v.equals("yes") || v.equals("on");
    }

    // armLoginWireBlock enables shouldBlockLoginWrite for the next on-wire login frame
    // ([type=16|18][u16 len][payload]). Called after plaintext capture in dump().
    public static void armLoginWireBlock(int wireFrameLen) {
        blockLoginWire = true;
        expectedWireLen = wireFrameLen;
        blockedWrites = 0;
        log("[LOGIN-BLOCK] armed for next login wire frame (~" + expectedWireLen + " bytes)");
    }

    // shouldBlockLoginWrite is invoked from instrumented java.net.SocketOutputStream.write.
    // Returns true to drop the write (login packet stays off the wire).
    public static boolean shouldBlockLoginWrite(byte[] b, int off, int len) {
        if (!blockLoginWire || b == null || len < 3 || off < 0 || off + len > b.length) {
            return false;
        }
        int type = b[off] & 0xff;
        if (type != 0x10 && type != 0x12) {
            return false;
        }
        int bodyLen = ((b[off + 1] & 0xff) << 8) | (b[off + 2] & 0xff);
        if (bodyLen < 40 || bodyLen > 4096) {
            return false;
        }
        int wireLen = bodyLen + 3;
        if (expectedWireLen > 0 && wireLen != expectedWireLen && len != expectedWireLen) {
            // Allow small mismatch (outer buffer may include slack); still block if type matches.
            if (len < wireLen - 8 || len > wireLen + 8) {
                return false;
            }
        }
        blockLoginWire = false;
        blockedWrites++;
        log("[LOGIN-BLOCK] dropped login socket write type=0x" + Integer.toHexString(type)
                + " wireLen=" + len + " bodyLen=" + bodyLen);
        try {
            Path marker = Paths.get(System.getProperty("user.home"), "login_wire_blocked.txt");
            Files.write(marker, ("blocked type=0x" + Integer.toHexString(type)
                    + " len=" + len + System.lineSeparator()).getBytes(),
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            pushHandoffIfConfigured();
        } catch (Throwable ignored) {
        }
        return true;
    }

    // pushHandoffIfConfigured sends capture state to HANDOFF_HOST:HANDOFF_PORT as
    // one JSON line (TCP). Docker publishes the port; the bot listens with HANDOFF_LISTEN.
    private static void pushHandoffIfConfigured() {
        String host = System.getProperty("handoff.host");
        if (host == null || host.isEmpty()) {
            host = System.getenv("HANDOFF_HOST");
        }
        String portStr = System.getProperty("handoff.port");
        if (portStr == null || portStr.isEmpty()) {
            portStr = System.getenv("HANDOFF_PORT");
        }
        if (host == null || host.isEmpty() || portStr == null || portStr.isEmpty()) {
            return;
        }
        try {
            Path home = Paths.get(System.getProperty("user.home"));
            String frameHex = readFrameHex(home.resolve("login_frame.txt"));
            String rsaHex = readTaggedHex(home.resolve("rsa_plaintext.txt"), "[RSA-PLAINTEXT]");
            String pk = readCcString(home.resolve("cc_strings.txt"), 1);
            String gf = readCcString(home.resolve("cc_strings.txt"), 3);
            if (frameHex.isEmpty() || rsaHex.isEmpty() || pk.isEmpty() || gf.isEmpty()) {
                log("[HANDOFF] skip: missing capture files");
                return;
            }
            String json = "{"
                    + "\"v\":1,"
                    + "\"gameSessionToken\":" + jsonString(pk) + ","
                    + "\"clientToken\":" + jsonString(gf) + ","
                    + "\"loginFrameHex\":" + jsonString(frameHex) + ","
                    + "\"rsaPlaintextHex\":" + jsonString(rsaHex) + ","
                    + "\"wireBlocked\":true"
                    + "}\n";
            int port = Integer.parseInt(portStr.trim());
            try (java.net.Socket s = new java.net.Socket()) {
                s.connect(new java.net.InetSocketAddress(host, port), 3000);
                s.getOutputStream().write(json.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                s.shutdownOutput();
            }
            log("[HANDOFF] pushed session to " + host + ":" + port + " (pk len=" + pk.length() + ")");
        } catch (Throwable t) {
            log("[HANDOFF] push failed: " + t);
        }
    }

    private static String jsonString(String s) {
        if (s == null) {
            return "\"\"";
        }
        StringBuilder sb = new StringBuilder(s.length() + 8);
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\': sb.append("\\\\"); break;
                case '"': sb.append("\\\""); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
        return sb.toString();
    }

    private static String readFrameHex(Path path) throws java.io.IOException {
        if (!Files.exists(path)) {
            return "";
        }
        String raw = new String(Files.readAllBytes(path), java.nio.charset.StandardCharsets.UTF_8);
        int i = raw.toLowerCase().indexOf("[login-frame]");
        if (i >= 0) {
            raw = raw.substring(i + "[LOGIN-FRAME]".length());
        }
        StringBuilder hex = new StringBuilder();
        for (int j = 0; j < raw.length(); j++) {
            char c = raw.charAt(j);
            if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
                hex.append(c);
            }
        }
        return hex.toString();
    }

    private static String readTaggedHex(Path path, String tag) throws java.io.IOException {
        if (!Files.exists(path)) {
            return "";
        }
        String raw = new String(Files.readAllBytes(path), java.nio.charset.StandardCharsets.UTF_8);
        int i = raw.indexOf(tag);
        if (i >= 0) {
            raw = raw.substring(i + tag.length());
        }
        StringBuilder hex = new StringBuilder();
        for (int j = 0; j < raw.length(); j++) {
            char c = raw.charAt(j);
            if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
                hex.append(c);
            }
        }
        return hex.toString();
    }

    private static String readCcString(Path path, int num) throws java.io.IOException {
        if (!Files.exists(path)) {
            return "";
        }
        String prefix = "#" + num + " ";
        for (String line : Files.readAllLines(path)) {
            if (line.startsWith(prefix)) {
                return line.substring(prefix.length()).trim();
            }
        }
        return "";
    }
}
