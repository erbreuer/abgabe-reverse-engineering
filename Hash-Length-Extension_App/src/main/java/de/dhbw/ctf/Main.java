package de.dhbw.ctf;

import java.io.InputStream;
import java.lang.reflect.Method;

public class Main {

    // "de.dhbw.ctf.Crypto" XOR 0x5A
    private static final byte[] _C = {0x3e,0x3f,0x74,0x3e,0x32,0x38,0x2d,0x74,0x39,0x2e,0x3c,0x74,0x19,0x28,0x23,0x2a,0x2e,0x35};

    // Methodennamen XOR 0x5A: a,b,c,d,e,f
    private static final byte[] _Ma = {0x3b};
    private static final byte[] _Mb = {0x38};
    private static final byte[] _Mc = {0x39};
    private static final byte[] _Md = {0x3e};
    private static final byte[] _Me = {0x3f};

    // Methodenname "f" XOR 0x5A
    private static final byte[] _Mf = {0x3c};

    private static String _s(byte[] b) {
        byte[] r = new byte[b.length];
        for (int i = 0; i < b.length; i++) r[i] = (byte) (b[i] ^ 0x5A);
        return new String(r, java.nio.charset.StandardCharsets.UTF_8);
    }

    static class EncryptedClassLoader extends ClassLoader {

        EncryptedClassLoader(ClassLoader parent) { super(parent); }

        @Override
        protected Class<?> findClass(String name) throws ClassNotFoundException {
            String path = name.replace('.', '/') + ".class.encrypted";
            try (InputStream in = getResourceAsStream(path)) {
                if (in == null) throw new ClassNotFoundException(path);
                byte[] data = in.readAllBytes();
                byte[] dec  = _d(data);
                return defineClass(name, dec, 0, dec.length);
            } catch (ClassNotFoundException e) {
                throw e;
            } catch (Exception e) {
                throw new ClassNotFoundException(name, e);
            }
        }

        // XOR-Schlüssel: 2^3 * 17 = 136 = 0x88, verschleiert
        private static final int _K = (int) (Math.pow(2, 3) * 17);

        private static byte[] _d(byte[] data) {
            byte[] r = data.clone();
            int n = r.length;
            for (int i = 0; i < n / 2; i++) {
                byte a = r[i];
                byte b = r[n - 1 - i];
                r[i]         = (byte) ((b ^ _K) & 0xFF);
                r[n - 1 - i] = (byte) ((a ^ _K) & 0xFF);
            }
            if (n % 2 == 1) r[n / 2] = (byte) ((r[n / 2] ^ _K) & 0xFF);
            return r;
        }
    }

    // --- internal validation ---
    private static boolean _chk(String s) {
        if (s == null || s.length() < 4) return false;
        int acc = ~(((int) Math.PI ^ Integer.MAX_VALUE >> 16) + Short.MAX_VALUE);
        for (int i = 0; i < s.length(); i++) acc ^= (s.charAt(i) << (i % 8));
        return (acc & 0xDEAD) == 0xBEEF;
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 0 || args[0].equals("--help") || args[0].equals("-h")) {
            printHelp();
            return;
        }

        EncryptedClassLoader loader = new EncryptedClassLoader(Main.class.getClassLoader());
        Class<?> crypto = loader.loadClass(_s(_C));

        // Trigger early ENV check — f() calls _secret() which throws if VAULT_SECRET is unset
        try {
            crypto.getMethod(_s(_Mf)).invoke(null);
        } catch (java.lang.reflect.InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause != null && cause.getMessage() != null && cause.getMessage().contains("VAULT_SECRET")) {
                System.err.println("Error: VAULT_SECRET environment variable not set.");
                System.exit(1);
            }
            throw e;
        }

        if (args[0].equals("--sample")) {
            String msg = (String) crypto.getMethod(_s(_Md)).invoke(null);
            String mac = (String) crypto.getMethod(_s(_Me)).invoke(null);
            System.out.println("Sample message (hex) : " + msg);
            System.out.println("Sample MAC           : " + mac);
            return;
        }

        if (args.length != 2) {
            System.err.println("Error: expected 2 arguments. Run with --help for usage.");
            System.exit(1);
        }

        String messageHex = args[0];
        String inputMac   = args[1];

        byte[] messageBytes;
        try {
            messageBytes = java.util.HexFormat.of().parseHex(messageHex);
        } catch (IllegalArgumentException e) {
            System.err.println("Error: message must be hex-encoded (e.g. 757365723d6775657374).");
            System.exit(1);
            return;
        }

        Method mComputeMac  = crypto.getMethod(_s(_Ma), byte[].class);
        Method mExtractRole = crypto.getMethod(_s(_Mb), byte[].class);
        Method mGetFlag     = crypto.getMethod(_s(_Mc));

        String expectedMac = (String) mComputeMac.invoke(null, (Object) messageBytes);

        if (!expectedMac.equalsIgnoreCase(inputMac)) {
            System.out.println("Access denied. Invalid MAC.");
            System.exit(1);
        }

        String role = (String) mExtractRole.invoke(null, (Object) messageBytes);

        if ("admin".equals(role)) {
            System.out.println("Access granted.");
            System.out.println((String) mGetFlag.invoke(null));
        } else {
            System.out.println("Access denied. You are: " + role);
            System.exit(1);
        }
    }

    static void printHelp() {
        System.out.println("VaultAccess - Token Validator");
        System.out.println();
        System.out.println("Usage:");
        System.out.println("  java -jar vault.jar <message-hex> <mac>");
        System.out.println("  java -jar vault.jar --sample");
        System.out.println("  java -jar vault.jar --help");
        System.out.println();
        System.out.println("Arguments:");
        System.out.println("  message-hex  The access token message, hex-encoded");
        System.out.println("  mac          SHA-256 MAC for the message (hex)");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  java -jar vault.jar --sample");
        System.out.println("  java -jar vault.jar 757365723d6775657374 <mac>");
    }
}
