package de.dhbw.securevault.obfuscator;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.SimpleRemapper;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.*;
import java.util.*;

/**
 * Standalone build-time obfuscation tool (kept separate from the core
 * Maven build on purpose, see CLAUDE.md #7 / SCHUTZKONZEPT.md).
 *
 * Applies, to the protected packages (keyparts, crypto, vault):
 *   1. Debug-info stripping (classes are compiled upstream with -g:none;
 *      this tool also strips via ASM as a safety net).
 *   2. Deterministic name mangling of classes/methods/fields via ASM
 *      ClassRemapper + SimpleRemapper, EXCEPT for a fixed "keep list" of
 *      symbols that Main.java references directly by string literal
 *      (the bootstrap contract into the protected world) -- those must
 *      keep stable names or the loader could never find them.
 *   3. Constant obfuscation is applied at source-authoring time in the
 *      KeyFragment* classes (bit-trick expressions) and simply preserved
 *      (not re-literalized) here.
 *
 * Usage: obfuscator <input-classes-dir> <output-dir> <rename-map-output.properties>
 */
public final class Obfuscator {

    // Fully qualified class names -> must NOT be renamed at the class level,
    // because Main.java calls Class.forName(...) on these names directly.
    private static final Set<String> KEEP_CLASS_NAMES = Set.of(
            "de/dhbw/securevault/keyparts/KeyAssembler",
            "de/dhbw/securevault/vault/FlagStore"
    );

    // "owner.methodName" + descriptor (SimpleRemapper's own key format, no
    // separator between name and descriptor) -> must not be renamed, since
    // Main.java calls getDeclaredMethod(...) with these exact names.
    private static final Set<String> KEEP_METHODS = Set.of(
            "de/dhbw/securevault/keyparts/KeyAssembler.reconstructKey(Ljava/lang/ClassLoader;[B)[B",
            "de/dhbw/securevault/vault/FlagStore.run(Ljava/lang/String;[BLjava/nio/file/Path;)V"
    );

    public static void main(String[] args) throws IOException {
        if (args.length != 3) {
            System.err.println("Usage: obfuscator <input-classes-dir> <output-dir> <rename-map.properties>");
            System.exit(2);
        }
        Path inputDir = Path.of(args[0]);
        Path outputDir = Path.of(args[1]);
        Path renameMapOut = Path.of(args[2]);

        List<Path> classFiles = new ArrayList<>();
        try (var stream = Files.walk(inputDir)) {
            stream.filter(p -> p.toString().endsWith(".class")).forEach(classFiles::add);
        }

        NameMangler mangler = new NameMangler(KEEP_CLASS_NAMES, KEEP_METHODS);
        Map<String, ClassReader> readers = new LinkedHashMap<>();
        for (Path classFile : classFiles) {
            byte[] bytes = Files.readAllBytes(classFile);
            ClassReader reader = new ClassReader(bytes);
            readers.put(reader.getClassName(), reader);
            mangler.scan(reader);
        }

        Map<String, String> renameMap = mangler.buildRenameMap();

        // Regenerate NameRegistry.java with the REAL post-obfuscation fragment
        // names baked in as literal string returns (see NameRegistryCodegen),
        // then recompile it so its own bytecode gets obfuscated + encrypted
        // just like every other protected class -- no plaintext properties
        // resource ships in the final jar.
        Path codegenWorkDir = Files.createTempDirectory("name-registry-codegen");
        Path recompiledRegistry = NameRegistryCodegen.regenerateAndCompile(renameMap, codegenWorkDir);
        ClassReader registryReader = new ClassReader(Files.readAllBytes(recompiledRegistry));
        readers.put(registryReader.getClassName(), registryReader);

        SimpleRemapper remapper = new SimpleRemapper(renameMap);
        Files.createDirectories(outputDir);
        for (Map.Entry<String, ClassReader> entry : readers.entrySet()) {
            ClassReader reader = entry.getValue();
            ClassWriter writer = new ClassWriter(0); // no COMPUTE_FRAMES: keep it simple/deterministic
            ClassRemapper remappingVisitor = new ClassRemapper(writer, remapper);
            // ClassReader.SKIP_DEBUG strips line numbers / local variable tables (technique #1)
            reader.accept(remappingVisitor, ClassReader.SKIP_DEBUG);

            String outputClassName = renameMap.getOrDefault(entry.getKey(), entry.getKey());
            Path outFile = outputDir.resolve(outputClassName + ".class");
            Files.createDirectories(outFile.getParent());
            try (OutputStream out = Files.newOutputStream(outFile)) {
                out.write(writer.toByteArray());
            }
        }

        writeRenameMapProperties(renameMap, renameMapOut);
        deleteRecursively(codegenWorkDir);

        System.out.println("Obfuscated " + classFiles.size() + " classes -> " + outputDir);
        System.out.println("Rename map written -> " + renameMapOut);
    }

    private static void deleteRecursively(Path dir) throws IOException {
        if (!Files.exists(dir)) {
            return;
        }
        try (var stream = Files.walk(dir)) {
            stream.sorted(Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.delete(p);
                } catch (IOException ignored) {
                    // best-effort cleanup of a temp dir
                }
            });
        }
    }

    private static void writeRenameMapProperties(Map<String, String> renameMap, Path out) throws IOException {
        Properties props = new Properties();
        // Only the fragment-related entries matter for NameRegistry; derive them
        // from the rename map by locating the three KeyFragment* classes.
        for (String frag : List.of("Alpha", "Beta", "Gamma")) {
            String original = "de/dhbw/securevault/keyparts/KeyFragment" + frag;
            String renamed = renameMap.getOrDefault(original, original);
            String prefix = frag.toLowerCase(Locale.ROOT);
            props.setProperty(prefix + ".class", renamed.replace('/', '.'));
            // method name "derive" for that owner (key format: owner + '.' + name + descriptor)
            String methodKey = renameMap.entrySet().stream()
                    .filter(e -> e.getKey().startsWith(original + ".derive("))
                    .map(Map.Entry::getValue)
                    .findFirst()
                    .orElse("derive");
            props.setProperty(prefix + ".method", methodKey);
        }
        Files.createDirectories(out.getParent());
        try (var writer = Files.newBufferedWriter(out)) {
            props.store(writer, "Generated by tools/obfuscator -- do not edit by hand");
        }
    }
}
