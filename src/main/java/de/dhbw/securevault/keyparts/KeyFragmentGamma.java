package de.dhbw.securevault.keyparts;

import java.security.MessageDigest;

/**
 * Fragment Gamma: SHA-256 over the bytes of a fixed resource packaged
 * inside the running JAR itself (vault/integrity.anchor), truncated to
 * 16 bytes. Couples the key to the concrete built artifact.
 */
public final class KeyFragmentGamma {

    private KeyFragmentGamma() {
    }

    public static byte[] derive(byte[] anchorBytes) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] digest = sha256.digest(anchorBytes);
            byte[] result = new byte[16];
            System.arraycopy(digest, 0, result, 0, 16);
            return result;
        } catch (Exception e) {
            throw new IllegalStateException("gamma derivation failure", e);
        }
    }
}
