package de.dhbw.securevault.keyparts;

/**
 * Resolves the runtime names of the protected fragment classes/methods
 * that KeyAssembler reaches via reflection. This source file holds the
 * identity mapping (original names) so the code is runnable and testable
 * before obfuscation. scripts/build.sh REGENERATES this exact file (see
 * tools/obfuscator's NameRegistryCodegen) with the real post-obfuscation
 * names baked in as literal string returns, then recompiles + obfuscates
 * only this one file as part of the protected bundle -- no separate
 * properties resource ships in the final jar, so the mapping is only
 * recoverable by decrypting and decompiling this class itself, exactly
 * like every other protected class.
 */
public final class NameRegistry {

    private NameRegistry() {
    }

    public static String alphaClass() {
        return "de.dhbw.securevault.keyparts.KeyFragmentAlpha";
    }

    public static String alphaMethod() {
        return "derive";
    }

    public static String betaClass() {
        return "de.dhbw.securevault.keyparts.KeyFragmentBeta";
    }

    public static String betaMethod() {
        return "derive";
    }

    public static String gammaClass() {
        return "de.dhbw.securevault.keyparts.KeyFragmentGamma";
    }

    public static String gammaMethod() {
        return "derive";
    }
}
