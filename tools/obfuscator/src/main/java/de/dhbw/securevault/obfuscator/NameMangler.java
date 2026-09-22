package de.dhbw.securevault.obfuscator;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.util.*;

/**
 * Scans a set of classes and produces a deterministic rename map for
 * ASM's SimpleRemapper: class internal names -> short names, and
 * "owner.name.descriptor" -> short method/field names, skipping anything
 * in the keep-lists and skipping constructors / static initializers
 * (which SimpleRemapper leaves alone regardless, but we avoid touching
 * their descriptors' method-name key).
 */
final class NameMangler {

    private final Set<String> keepClassNames;
    private final Set<String> keepMethods;

    private final Set<String> classInternalNames = new TreeSet<>();
    // key: owner#name#descriptor (method), value assigned name
    private final Set<String> methodKeys = new TreeSet<>();
    private final Set<String> fieldKeys = new TreeSet<>();

    NameMangler(Set<String> keepClassNames, Set<String> keepMethods) {
        this.keepClassNames = keepClassNames;
        this.keepMethods = keepMethods;
    }

    void scan(ClassReader reader) {
        classInternalNames.add(reader.getClassName());
        reader.accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                              String signature, String[] exceptions) {
                if (!name.equals("<init>") && !name.equals("<clinit>")) {
                    methodKeys.add(reader.getClassName() + "#" + name + "#" + descriptor);
                }
                return null;
            }

            @Override
            public FieldVisitor visitField(int access, String name, String descriptor,
                                            String signature, Object value) {
                fieldKeys.add(reader.getClassName() + "#" + name + "#" + descriptor);
                return null;
            }
        }, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG);
    }

    Map<String, String> buildRenameMap() {
        Map<String, String> map = new LinkedHashMap<>();
        NameSequence classNames = new NameSequence();
        for (String internalName : classInternalNames) {
            if (keepClassNames.contains(internalName)) {
                continue;
            }
            map.put(internalName, packageOf(internalName) + classNames.next());
        }

        NameSequence methodNames = new NameSequence();
        for (String key : methodKeys) {
            String[] parts = key.split("#", 3);
            String owner = parts[0];
            String methodName = parts[1];
            String descriptor = parts[2];
            // SimpleRemapper's own key format is owner + '.' + name + descriptor
            // (no separator between name and descriptor -- descriptor starts with '(').
            String remapperKey = owner + "." + methodName + descriptor;
            if (keepMethods.contains(remapperKey)) {
                continue;
            }
            map.put(remapperKey, methodNames.next());
        }

        NameSequence fieldNames = new NameSequence();
        for (String key : fieldKeys) {
            String[] parts = key.split("#", 3);
            String owner = parts[0];
            String fieldName = parts[1];
            map.put(owner + "." + fieldName, fieldNames.next());
        }

        return map;
    }

    private static String packageOf(String internalName) {
        int idx = internalName.lastIndexOf('/');
        return idx < 0 ? "" : internalName.substring(0, idx + 1);
    }

    /** a, b, c, ..., z, aa, ab, ... deterministic short-name generator. */
    private static final class NameSequence {
        private int counter = 0;

        String next() {
            int n = counter++;
            StringBuilder sb = new StringBuilder();
            do {
                sb.append((char) ('a' + (n % 26)));
                n = n / 26 - 1;
            } while (n >= 0);
            return sb.reverse().toString();
        }
    }
}
