package de.dhbw.securevault.keyparts;

/**
 * Fragment Alpha: 8 deterministic bytes computed from obfuscated-looking
 * constant expressions. SEED_A/SEED_B are routed through a non-inlinable
 * static method call (not a compile-time constant field) specifically so
 * javac cannot constant-fold the surrounding bit operations away -- the
 * actual ixor/ixor/ishr/isub instructions must survive into the .class
 * file for this to be a real obfuscation technique rather than a source-
 * level-only one.
 */
public final class KeyFragmentAlpha {

    private static final int SEED_A = obtainSeedA();
    private static final int SEED_B = obtainSeedB();

    private KeyFragmentAlpha() {
    }

    public static byte[] derive() {
        int wordA = (~(SEED_A ^ 0x3C3C0000)) + 0x1234;
        int wordB = ((SEED_B >>> 3) ^ 0x0F0F0F0F) - 0x77777777;

        byte[] result = new byte[8];
        writeIntBigEndian(result, 0, wordA);
        writeIntBigEndian(result, 4, wordB);
        return result;
    }

    // Not "static final int SEED_A = 0x5A5A5A5A;" on purpose: a directly
    // inlined constant field would still let javac fold derive()'s whole
    // expression into one literal. Going through a method call forces the
    // bit operations themselves into the compiled bytecode.
    private static int obtainSeedA() {
        return 0x5A5A5A5A;
    }

    private static int obtainSeedB() {
        return 0x7FFFFFFF;
    }

    private static void writeIntBigEndian(byte[] dest, int offset, int value) {
        dest[offset] = (byte) (value >>> 24);
        dest[offset + 1] = (byte) (value >>> 16);
        dest[offset + 2] = (byte) (value >>> 8);
        dest[offset + 3] = (byte) value;
    }
}
