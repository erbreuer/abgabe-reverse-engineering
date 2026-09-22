package de.dhbw.securevault.obfuscator;

import javax.tools.JavaCompiler;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import java.io.IOException;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Regenerates NameRegistry.java with the real post-obfuscation fragment
 * names baked in as literal string returns (instead of a shipped properties
 * resource, which would let an attacker read the class/method mapping with
 * a plain `unzip -p` and no decompilation at all). Compiles the regenerated
 * source with -g:none, matching the debug-info-stripping applied to every
 * other protected class.
 */
final class NameRegistryCodegen {

    private NameRegistryCodegen() {
    }

    /**
     * @param renameMap       the rename map already computed for classes/methods/fields
     * @param workDir         scratch directory to write the regenerated source + recompiled class into
     * @return path to the recompiled NameRegistry.class (pre-obfuscation-rename, post-codegen)
     */
    static Path regenerateAndCompile(java.util.Map<String, String> renameMap, Path workDir) throws IOException {
        String alphaClass = dotted(renameMap.getOrDefault(
                "de/dhbw/securevault/keyparts/KeyFragmentAlpha", "de/dhbw/securevault/keyparts/KeyFragmentAlpha"));
        String alphaMethod = resolveMethodName(renameMap, "de/dhbw/securevault/keyparts/KeyFragmentAlpha", "derive");

        String betaClass = dotted(renameMap.getOrDefault(
                "de/dhbw/securevault/keyparts/KeyFragmentBeta", "de/dhbw/securevault/keyparts/KeyFragmentBeta"));
        String betaMethod = resolveMethodName(renameMap, "de/dhbw/securevault/keyparts/KeyFragmentBeta", "derive");

        String gammaClass = dotted(renameMap.getOrDefault(
                "de/dhbw/securevault/keyparts/KeyFragmentGamma", "de/dhbw/securevault/keyparts/KeyFragmentGamma"));
        String gammaMethod = resolveMethodName(renameMap, "de/dhbw/securevault/keyparts/KeyFragmentGamma", "derive");

        String source = """
                package de.dhbw.securevault.keyparts;

                public final class NameRegistry {
                    private NameRegistry() {
                    }

                    public static String alphaClass() {
                        return "%s";
                    }

                    public static String alphaMethod() {
                        return "%s";
                    }

                    public static String betaClass() {
                        return "%s";
                    }

                    public static String betaMethod() {
                        return "%s";
                    }

                    public static String gammaClass() {
                        return "%s";
                    }

                    public static String gammaMethod() {
                        return "%s";
                    }
                }
                """.formatted(alphaClass, alphaMethod, betaClass, betaMethod, gammaClass, gammaMethod);

        Path sourceDir = workDir.resolve("src/de/dhbw/securevault/keyparts");
        Files.createDirectories(sourceDir);
        Path sourceFile = sourceDir.resolve("NameRegistry.java");
        Files.writeString(sourceFile, source);

        Path outDir = workDir.resolve("classes");
        Files.createDirectories(outDir);

        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        try (StandardJavaFileManager fileManager =
                     compiler.getStandardFileManager(null, null, null)) {
            Iterable<? extends javax.tools.JavaFileObject> units =
                    fileManager.getJavaFileObjectsFromPaths(List.of(sourceFile));
            StringWriterErr diagnostics = new StringWriterErr();
            boolean success = compiler.getTask(
                    diagnostics, fileManager, null,
                    List.of("-g:none", "--release", "21", "-d", outDir.toString()),
                    null, units
            ).call();
            if (!success) {
                throw new IOException("failed to compile regenerated NameRegistry.java:\n" + diagnostics);
            }
        }

        return outDir.resolve("de/dhbw/securevault/keyparts/NameRegistry.class");
    }

    private static String resolveMethodName(java.util.Map<String, String> renameMap, String owner,
                                             String defaultName) {
        // Look up any rename-map entry for owner + ".derive" regardless of its
        // exact descriptor (varies per fragment) and take its mapped value.
        for (var entry : renameMap.entrySet()) {
            if (entry.getKey().startsWith(owner + ".derive(")) {
                return entry.getValue();
            }
        }
        return defaultName;
    }

    private static String dotted(String internalName) {
        return internalName.replace('/', '.');
    }

    private static final class StringWriterErr extends Writer {
        private final StringBuilder sb = new StringBuilder();

        @Override
        public void write(char[] cbuf, int off, int len) {
            sb.append(cbuf, off, len);
        }

        @Override
        public void flush() {
        }

        @Override
        public void close() {
        }

        @Override
        public String toString() {
            return sb.toString();
        }
    }
}
