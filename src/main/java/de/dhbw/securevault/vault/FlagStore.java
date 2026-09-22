package de.dhbw.securevault.vault;

import de.dhbw.securevault.crypto.VaultCipher;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Reads/writes the encrypted flag resource. The plaintext structure is a
 * repeating 16-byte block ("PADPADPADPADPAD" style) followed by the real
 * flag text, so that identical AES/ECB blocks are visible in a hex dump
 * of flag.enc even without knowing the key.
 */
public final class FlagStore {

    private static final String FLAG_RESOURCE = "flag.enc";
    private static final byte[] PADDING_BLOCK =
            "PADPADPADPADPAD-".getBytes(StandardCharsets.US_ASCII); // 16 bytes
    private static final int PADDING_REPETITIONS = 4;

    private FlagStore() {
    }

    /** Entry point invoked reflectively by Main via VaultClassLoader. */
    public static void run(String mode, byte[] key, Path outPath) throws IOException {
        if ("encrypt".equals(mode)) {
            String flagText = System.getProperty("securevault.flagtext", "FLAG{}");
            writeEncryptedFlag(flagText, key, outPath);
        } else if ("decrypt".equals(mode)) {
            String plaintext = readAndDecryptFlag(key);
            if (outPath != null) {
                Files.writeString(outPath, plaintext, StandardCharsets.UTF_8);
            } else {
                System.out.println(plaintext);
            }
        } else {
            throw new IllegalArgumentException("unknown mode: " + mode);
        }
    }

    static byte[] buildPaddedPlaintext(String flagText) {
        byte[] flagBytes = flagText.getBytes(StandardCharsets.UTF_8);
        byte[] result = new byte[PADDING_BLOCK.length * PADDING_REPETITIONS + flagBytes.length];
        int pos = 0;
        for (int i = 0; i < PADDING_REPETITIONS; i++) {
            System.arraycopy(PADDING_BLOCK, 0, result, pos, PADDING_BLOCK.length);
            pos += PADDING_BLOCK.length;
        }
        System.arraycopy(flagBytes, 0, result, pos, flagBytes.length);
        return result;
    }

    static String stripPadding(byte[] decrypted) {
        int skip = PADDING_BLOCK.length * PADDING_REPETITIONS;
        return new String(decrypted, skip, decrypted.length - skip, StandardCharsets.UTF_8);
    }

    private static void writeEncryptedFlag(String flagText, byte[] key, Path outPath) throws IOException {
        byte[] padded = buildPaddedPlaintext(flagText);
        byte[] ciphertext = VaultCipher.encrypt(padded, key);
        Path target = outPath != null ? outPath : Path.of(FLAG_RESOURCE);
        Files.write(target, ciphertext);
    }

    private static String readAndDecryptFlag(byte[] key) throws IOException {
        byte[] ciphertext = loadFlagResourceBytes();
        byte[] decrypted = VaultCipher.decrypt(ciphertext, key);
        return stripPadding(decrypted);
    }

    private static byte[] loadFlagResourceBytes() throws IOException {
        Path direct = Path.of(FLAG_RESOURCE);
        if (Files.exists(direct)) {
            return Files.readAllBytes(direct);
        }
        try (InputStream in = FlagStore.class.getClassLoader().getResourceAsStream(FLAG_RESOURCE)) {
            if (in == null) {
                throw new IOException("flag.enc not found on classpath or in working directory");
            }
            return in.readAllBytes();
        }
    }
}
