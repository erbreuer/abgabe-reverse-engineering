package de.dhbw.securevault.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES/ECB/PKCS5Padding, no IV, no salt, no integrity check.
 */
public final class VaultCipher {

    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";

    private VaultCipher() {
    }

    public static byte[] encrypt(byte[] plaintext, byte[] key) {
        return run(Cipher.ENCRYPT_MODE, plaintext, key);
    }

    public static byte[] decrypt(byte[] ciphertext, byte[] key) {
        return run(Cipher.DECRYPT_MODE, ciphertext, key);
    }

    private static byte[] run(int mode, byte[] input, byte[] key) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(mode, new SecretKeySpec(key, "AES"));
            return cipher.doFinal(input);
        } catch (Exception e) {
            throw new IllegalStateException("vault cipher failure", e);
        }
    }
}
