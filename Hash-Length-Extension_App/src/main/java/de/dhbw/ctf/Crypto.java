package de.dhbw.ctf;

import java.security.MessageDigest;
import java.util.HexFormat;
import java.nio.charset.StandardCharsets;

public class Crypto {

    // Flag, verschlüsselt mit einem aus SHA-256(secret || _FREF) abgeleiteten
    // Keystream (siehe _keystream/c() unten). Wird von build.sh neu erzeugt,
    // sobald sich das eingebettete Secret ändert.
    private static final byte[] _F = {116,62,-100,25,-14,-46,-11,-103,47,101,90,37,-88,-83,66,-39,71,8,-93,40,12,124,15,76,-111,-84,64,-18,-8,-29,116,66,-109};

    // Bindet die Flag-Entschlüsselung an das Secret, unabhängig von der
    // konkret geprüften Nachricht.
    private static final byte[] _FREF = "vault-flag".getBytes(StandardCharsets.UTF_8);

    private static final byte[] _M = "user=guest".getBytes(StandardCharsets.UTF_8);

    // Secret, verteilt über vier Fragmente: eine lokale Konstante, das
    // Manifest-Attribut X-Secret-Tag (von build.sh gesetzt), der
    // Loader-Schlüssel aus Main.EncryptedClassLoader._key() (selbst schon
    // aus vier Anteilen zusammengesetzt, siehe dort) und
    // RuntimeTag.TRACE_TAG. Wie beim Loader-Schlüssel werden die Anteile
    // über SHA-256 verdichtet statt nur XOR-verknüpft (siehe
    // Main.EncryptedClassLoader._deriveKey) — wer nicht alle vier
    // Fragmente exakt korrekt kombiniert, bekommt keinen teilweise
    // brauchbaren, sondern einen komplett anderen Schlüssel. Der dritte
    // Anteil ist bewusst kein Compile-Zeit-Literal wie die anderen,
    // sondern das Ergebnis eines echten Laufzeit-Methodenaufrufs (liest
    // erneut das Manifest) — javac kann ihn deshalb nicht mit den anderen
    // Fragmenten zu einer einzigen Konstante zusammenfalten, und Main und
    // Crypto lassen sich nicht mehr unabhängig voneinander lösen.
    private static final int _S1 = 0x6F;
    private static final byte[] _S = {33,39,101,32,55,97,49,58,39,115,10,25,102,59,50,33,61,10,16,45,33,102,59,38,60,58,59,10,6,48,54,39,102,33,116,116};

    private static int _secretManifestTag() {
        try (java.io.InputStream in = Crypto.class.getClassLoader()
                .getResourceAsStream("META-INF/MANIFEST.MF")) {
            if (in == null) throw new IllegalStateException("manifest missing");
            java.util.jar.Manifest mf = new java.util.jar.Manifest(in);
            String v = mf.getMainAttributes().getValue("X-Secret-Tag");
            if (v == null) throw new IllegalStateException("X-Secret-Tag missing");
            return Integer.parseInt(v.trim());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] _secret() {
        int key = Main.EncryptedClassLoader._deriveKey(
                _S1, _secretManifestTag(), Main.EncryptedClassLoader._key(), RuntimeTag.TRACE_TAG);
        byte[] r = new byte[_S.length];
        for (int i = 0; i < _S.length; i++) r[i] = (byte) (_S[i] ^ key);
        return r;
    }

    private static byte[] _keystream(int len) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] block = md.digest(_concat(_secret(), _FREF));
            byte[] out = new byte[len];
            int pos = 0;
            while (pos < len) {
                if (pos > 0) block = md.digest(block);
                int n = Math.min(block.length, len - pos);
                System.arraycopy(block, 0, out, pos, n);
                pos += n;
            }
            return out;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] _concat(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    // computeMac
    public static String a(byte[] m) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(_concat(_secret(), m));
            return HexFormat.of().formatHex(hash);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // extractRole — letztes user= gewinnt
    public static String b(byte[] m) {
        String r = "unknown";
        for (String p : new String(m, StandardCharsets.UTF_8).split("&")) {
            if (p.startsWith("user=")) r = p.substring(5);
        }
        return r;
    }

    // getFlag
    public static String c() {
        byte[] ks = _keystream(_F.length);
        byte[] r = new byte[_F.length];
        for (int i = 0; i < _F.length; i++) r[i] = (byte) (_F[i] ^ ks[i]);
        return new String(r, StandardCharsets.UTF_8);
    }

    // getSampleMessage (hex-encoded)
    public static String d() { return HexFormat.of().formatHex(_M); }

    // getSampleMac
    public static String e() { return a(_M); }

    // getSecretLength: verschleiert über Integer-Rotation
    public static int f() { return Integer.rotateRight(Integer.rotateLeft(_secret().length, 3), 3); }
    // --- internal validation ---

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
