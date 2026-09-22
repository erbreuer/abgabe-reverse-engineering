package de.dhbw.securevault.keyparts;

import java.lang.reflect.Method;
import java.security.MessageDigest;

/**
 * Combines Alpha, Beta and Gamma into the final 256-bit AES key. Every
 * fragment is loaded through the supplied ClassLoader (normally the
 * VaultClassLoader instance that loaded KeyAssembler itself) and invoked
 * only via reflection -- the three fragment classes are never referenced
 * directly by name in bytecode-visible form beyond the NameRegistry lookup.
 */
public final class KeyAssembler {

    private KeyAssembler() {
    }

    public static byte[] reconstructKey(ClassLoader loader, byte[] manifestBytes) throws Exception {
        byte[] alpha = invoke(loader, NameRegistry.alphaClass(), NameRegistry.alphaMethod(),
                new Class<?>[0], new Object[0]);
        byte[] beta = invoke(loader, NameRegistry.betaClass(), NameRegistry.betaMethod(),
                new Class<?>[]{byte[].class}, new Object[]{alpha});
        byte[] gamma = invoke(loader, NameRegistry.gammaClass(), NameRegistry.gammaMethod(),
                new Class<?>[]{byte[].class}, new Object[]{manifestBytes});

        return concatAndHash(alpha, beta, gamma);
    }

    private static byte[] invoke(ClassLoader loader, String className, String methodName,
                                  Class<?>[] paramTypes, Object[] args) throws Exception {
        Class<?> clazz = Class.forName(className, true, loader);
        Method method = clazz.getDeclaredMethod(methodName, paramTypes);
        method.setAccessible(true);
        return (byte[]) method.invoke(null, args);
    }

    private static byte[] concatAndHash(byte[] alpha, byte[] beta, byte[] gamma) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        sha256.update(alpha);
        sha256.update(beta);
        sha256.update(gamma);
        return sha256.digest(); // 32 bytes = 256-bit AES key
    }
}
