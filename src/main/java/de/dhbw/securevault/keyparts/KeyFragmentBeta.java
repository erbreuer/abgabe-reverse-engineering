package de.dhbw.securevault.keyparts;

import java.security.MessageDigest;

/**
 * Fragment Beta: derived from Alpha's output via an HMAC-style mixing step
 * (SHA-256 over alpha || fixed pepper, truncated to 8 bytes). KeyAssembler
 * calls this only via reflection, after obtaining Alpha's output the same way.
 */
public final class KeyFragmentBeta {

    private static final byte[] PEPPER = {
            (byte) 0x42, (byte) 0xC0, (byte) 0xFF, (byte) 0xEE,
            (byte) 0x13, (byte) 0x37, (byte) 0x13, (byte) 0x37
    };

    private KeyFragmentBeta() {
    }

    public static byte[] derive(byte[] alpha) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            sha256.update(alpha);
            sha256.update(PEPPER);
            byte[] digest = sha256.digest();
            byte[] result = new byte[8];
            System.arraycopy(digest, 0, result, 0, 8);
            return result;
        } catch (Exception e) {
            throw new IllegalStateException("beta derivation failure", e);
        }
    }
}
