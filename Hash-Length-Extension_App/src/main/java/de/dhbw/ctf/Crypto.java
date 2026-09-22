package de.dhbw.ctf;

import java.security.MessageDigest;
import java.util.HexFormat;

public class Crypto {

    // SECRET "s3cr3t!X" XOR 0x42
    private static final byte[] _S = {0x31,0x71,0x21,0x30,0x71,0x36,0x63,0x1a};

    // FLAG XOR 0x42
    private static final byte[] _F = {0x4,0xe,0x3,0x5,0x39,0x2a,0x76,0x31,0x2a,0x1d,0x2e,0x71,0x2c,0x25,0x36,0x2a,0x1d,0x71,0x3a,0x36,0x71,0x2c,0x31,0x73,0x72,0x2c,0x1d,0x32,0x35,0x2c,0x71,0x26,0x3f};

    // SECRET_LENGTH: (int)(ln(e^8)) = 8, verschleiert
    private static final int _L = (int) Math.round(Math.log(Math.exp(8)));

    private static final String _M = "user=guest";

    private static String _x(byte[] b) {
        byte[] r = new byte[b.length];
        for (int i = 0; i < b.length; i++) r[i] = (byte) (b[i] ^ 0x42);
        return new String(r, java.nio.charset.StandardCharsets.UTF_8);
    }

    // computeMac
    public static String a(String m) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] input = (_x(_S) + m).getBytes("UTF-8");
            byte[] hash = md.digest(input);
            return HexFormat.of().formatHex(hash);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // extractRole — letztes user= gewinnt
    public static String b(String m) {
        String r = "unknown";
        for (String p : m.split("&")) {
            if (p.startsWith("user=")) r = p.substring(5);
        }
        return r;
    }

    // getFlag
    public static String c() { return _x(_F); }

    // getSampleMessage
    public static String d() { return _M; }

    // getSampleMac
    public static String e() { return a(_M); }

    // getSecretLength
    public static int f() { return _L; }

    // --- toter Code: sieht aus wie Lizenzprüfung, wird nie aufgerufen ---

    private static int _h(String s) {
        int h = 0x1505;
        for (char c : s.toCharArray()) h = h * 33 + c;
        return h & 0xFFFFFF;
    }

    private static boolean _v(String k) {
        int[] ref = {0x4f, 0x2a, 0x91, 0xb3};
        byte[] kb = k.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        for (int i = 0; i < Math.min(kb.length, ref.length); i++) {
            if ((kb[i] ^ ref[i]) != (i * 7 + 3)) return false;
        }
        return kb.length >= ref.length;
    }

    private static String _r(String s) {
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            if (c >= 'a' && c <= 'z') sb.append((char)('a' + (c - 'a' + 13) % 26));
            else if (c >= 'A' && c <= 'Z') sb.append((char)('A' + (c - 'A' + 13) % 26));
            else sb.append(c);
        }
        return sb.toString();
    }
}
