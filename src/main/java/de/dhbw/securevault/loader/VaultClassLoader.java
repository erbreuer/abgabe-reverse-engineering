package de.dhbw.securevault.loader;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Loads the protected de.dhbw.securevault.{keyparts,crypto,vault} classes
 * from encrypted resources (resources/vault/<name>.bin) at runtime.
 *
 * The AES-256-GCM key below only protects against casual `unzip` + `javap`
 * inspection of the shipped resources -- it is intentionally visible here.
 * It is NOT the flag's encryption key; that key is reconstructed separately
 * and non-trivially by KeyAssembler (see the keyparts package).
 */
public class VaultClassLoader extends ClassLoader {

    // Bootstrap resource-decryption key. Intentionally hardcoded and visible:
    // this only protects the *packaging*, not the actual puzzle.
    private static final byte[] BOOTSTRAP_KEY = {
            (byte) 0x2B, (byte) 0x7E, (byte) 0x15, (byte) 0x16,
            (byte) 0x28, (byte) 0xAE, (byte) 0xD2, (byte) 0xA6,
            (byte) 0xAB, (byte) 0xF7, (byte) 0x15, (byte) 0x88,
            (byte) 0x09, (byte) 0xCF, (byte) 0x4F, (byte) 0x3C,
            (byte) 0x76, (byte) 0x2E, (byte) 0x71, (byte) 0x60,
            (byte) 0xF3, (byte) 0x8B, (byte) 0x4D, (byte) 0xA5,
            (byte) 0x6A, (byte) 0x78, (byte) 0x4D, (byte) 0x90,
            (byte) 0x45, (byte) 0x19, (byte) 0x0C, (byte) 0xFE
    };
    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_IV_LENGTH = 12;

    public VaultClassLoader(ClassLoader parent) {
        super(parent);
    }

    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
        try (InputStream in = getResourceAsStream(toResourcePath(name))) {
            if (in == null) {
                throw new ClassNotFoundException("no encrypted resource for " + name);
            }
            byte[] encryptedBytes = in.readAllBytes();
            byte[] classBytes = decrypt(encryptedBytes, BOOTSTRAP_KEY);
            return defineClass(name, classBytes, 0, classBytes.length);
        } catch (IOException e) {
            throw new ClassNotFoundException("failed loading " + name, e);
        }
    }

    private static String toResourcePath(String className) {
        return "vault/" + className.replace('.', '_') + ".bin";
    }

    private static byte[] decrypt(byte[] input, byte[] key) {
        try {
            byte[] iv = new byte[GCM_IV_LENGTH];
            System.arraycopy(input, 0, iv, 0, GCM_IV_LENGTH);
            byte[] ciphertextAndTag = new byte[input.length - GCM_IV_LENGTH];
            System.arraycopy(input, GCM_IV_LENGTH, ciphertextAndTag, 0, ciphertextAndTag.length);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, iv));
            return cipher.doFinal(ciphertextAndTag);
        } catch (Exception e) {
            throw new IllegalStateException("bootstrap decryption failure", e);
        }
    }

    // Fixed resource name that KeyFragmentGamma hashes for its JAR-self-
    // integrity coupling. Deliberately NOT META-INF/MANIFEST.MF: Maven's
    // archiver always merges in its own extra attributes (Created-By,
    // Build-Jdk-Spec, ...) even when given an explicit manifestFile, which
    // would make the packaged bytes differ from what the build computed
    // the flag's key from. This anchor file is a plain resource that Maven
    // copies byte-for-byte, so build-time and run-time hashes always match.
    private static final String INTEGRITY_ANCHOR_RESOURCE = "vault/integrity.anchor";

    /** Reads the fixed, build-generated integrity-anchor resource bytes. */
    public byte[] readIntegrityAnchorBytes() throws IOException {
        try (InputStream in = getResourceAsStream(INTEGRITY_ANCHOR_RESOURCE)) {
            if (in != null) {
                return in.readAllBytes();
            }
        }
        Path staged = Path.of("resources/" + INTEGRITY_ANCHOR_RESOURCE);
        if (Files.exists(staged)) {
            return Files.readAllBytes(staged);
        }
        throw new IOException("could not locate " + INTEGRITY_ANCHOR_RESOURCE);
    }
}
