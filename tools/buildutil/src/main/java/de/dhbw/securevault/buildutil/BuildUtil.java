package de.dhbw.securevault.buildutil;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;

/**
 * Build-time helper invoked by scripts/build.sh. Not shipped in the final
 * JAR. Performs the two steps that must happen outside the "protected"
 * runtime path (since they need to WRITE encrypted artifacts, not load
 * them): bootstrap-encrypting the obfuscated .class files into
 * resources/vault/*.bin, and generating flag.enc via the exact same key
 * derivation KeyAssembler performs at runtime (duplicated here directly,
 * without reflection, since this tool has ordinary classpath access and
 * is not part of the puzzle).
 *
 * Subcommands:
 *   encrypt-classes <obfuscated-dir> <resources/vault-dir>
 *   generate-anchor <output-anchor-file>
 *   generate-flag <anchor-file> <flag-text> <output-flag.enc>
 *   print-key <anchor-file>
 */
public final class BuildUtil {

    // Must be IDENTICAL to VaultClassLoader.BOOTSTRAP_KEY.
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
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_BITS = 128;

    private static final byte[] PADDING_BLOCK =
            "PADPADPADPADPAD-".getBytes(StandardCharsets.US_ASCII);
    private static final int PADDING_REPETITIONS = 4;

    private static final byte[] BETA_PEPPER = {
            (byte) 0x42, (byte) 0xC0, (byte) 0xFF, (byte) 0xEE,
            (byte) 0x13, (byte) 0x37, (byte) 0x13, (byte) 0x37
    };

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.err.println("missing subcommand");
            System.exit(2);
        }
        switch (args[0]) {
            case "encrypt-classes" -> encryptClasses(Path.of(args[1]), Path.of(args[2]));
            case "generate-anchor" -> generateAnchor(Path.of(args[1]));
            case "generate-flag" -> generateFlag(Path.of(args[1]), args[2], Path.of(args[3]));
            case "print-key" -> printKey(Path.of(args[1]));
            default -> {
                System.err.println("unknown subcommand: " + args[0]);
                System.exit(2);
            }
        }
    }

    private static void encryptClasses(Path obfuscatedDir, Path vaultOutDir) throws IOException {
        Files.createDirectories(vaultOutDir);
        List<Path> classFiles = new ArrayList<>();
        try (var stream = Files.walk(obfuscatedDir)) {
            stream.filter(p -> p.toString().endsWith(".class")).forEach(classFiles::add);
        }
        for (Path classFile : classFiles) {
            String relative = obfuscatedDir.relativize(classFile).toString();
            String className = relative.substring(0, relative.length() - ".class".length())
                    .replace('/', '.').replace('\\', '.');
            byte[] classBytes = Files.readAllBytes(classFile);
            byte[] encrypted = encryptGcm(classBytes, BOOTSTRAP_KEY);
            Path outFile = vaultOutDir.resolve(className.replace('.', '_') + ".bin");
            Files.write(outFile, encrypted);
            System.out.println("encrypted " + className + " -> " + outFile);
        }
    }

    private static byte[] encryptGcm(byte[] plaintext, byte[] key) throws IOException {
        try {
            byte[] iv = new byte[GCM_IV_LENGTH];
            new SecureRandom().nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] ciphertextAndTag = cipher.doFinal(plaintext);
            byte[] result = new byte[GCM_IV_LENGTH + ciphertextAndTag.length];
            System.arraycopy(iv, 0, result, 0, GCM_IV_LENGTH);
            System.arraycopy(ciphertextAndTag, 0, result, GCM_IV_LENGTH, ciphertextAndTag.length);
            return result;
        } catch (Exception e) {
            throw new IOException("bootstrap encryption failure", e);
        }
    }

    private static void generateAnchor(Path outFile) throws IOException {
        Files.createDirectories(outFile.getParent());
        // Fixed, deterministic content -- no timestamps, no build-machine-
        // specific data. This exact byte content is what KeyFragmentGamma
        // hashes, both here at build time and at runtime once the same
        // file is packaged into the JAR as a plain (Maven-untouched)
        // resource. See VaultClassLoader.INTEGRITY_ANCHOR_RESOURCE.
        String content = "SecureVault-RE integrity anchor v1\n"
                + "artifact=de.dhbw.securevault:securevault-re\n"
                + "main-class=de.dhbw.securevault.Main\n";
        Files.write(outFile, content.getBytes(StandardCharsets.UTF_8));
        System.out.println("generated integrity anchor -> " + outFile);
    }

    private static void generateFlag(Path anchorFile, String flagText, Path outFlagEnc) throws Exception {
        byte[] key = reconstructKey(anchorFile);
        byte[] padded = buildPaddedPlaintext(flagText);
        byte[] ciphertext = aesEcbEncrypt(padded, key);
        Files.write(outFlagEnc, ciphertext);
        System.out.println("wrote " + outFlagEnc + " (" + ciphertext.length + " bytes)");
    }

    private static void printKey(Path anchorFile) throws Exception {
        byte[] key = reconstructKey(anchorFile);
        System.out.println(toHex(key));
    }

    private static byte[] reconstructKey(Path anchorFile) throws Exception {
        byte[] anchorBytes = Files.readAllBytes(anchorFile);

        // Alpha: identical expressions to KeyFragmentAlpha.derive()
        int wordA = (~(0x5A5A5A5A ^ 0x3C3C0000)) + 0x1234;
        int wordB = ((0x7FFFFFFF >>> 3) ^ 0x0F0F0F0F) - 0x77777777;
        byte[] alpha = new byte[8];
        writeIntBigEndian(alpha, 0, wordA);
        writeIntBigEndian(alpha, 4, wordB);

        // Beta: identical to KeyFragmentBeta.derive(alpha)
        MessageDigest sha256Beta = MessageDigest.getInstance("SHA-256");
        sha256Beta.update(alpha);
        sha256Beta.update(BETA_PEPPER);
        byte[] beta = Arrays.copyOf(sha256Beta.digest(), 8);

        // Gamma: identical to KeyFragmentGamma.derive(anchorBytes)
        MessageDigest sha256Gamma = MessageDigest.getInstance("SHA-256");
        byte[] gamma = Arrays.copyOf(sha256Gamma.digest(anchorBytes), 16);

        // final key: identical to KeyAssembler.concatAndHash(alpha, beta, gamma)
        MessageDigest sha256Final = MessageDigest.getInstance("SHA-256");
        sha256Final.update(alpha);
        sha256Final.update(beta);
        sha256Final.update(gamma);
        return sha256Final.digest();
    }

    private static void writeIntBigEndian(byte[] dest, int offset, int value) {
        dest[offset] = (byte) (value >>> 24);
        dest[offset + 1] = (byte) (value >>> 16);
        dest[offset + 2] = (byte) (value >>> 8);
        dest[offset + 3] = (byte) value;
    }

    private static byte[] buildPaddedPlaintext(String flagText) {
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

    private static byte[] aesEcbEncrypt(byte[] plaintext, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        return cipher.doFinal(plaintext);
    }

    private static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) {
            sb.append(String.format("%02x", x));
        }
        return sb.toString();
    }
}
