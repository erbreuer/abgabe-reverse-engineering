package de.dhbw.securevault.cli;

import java.nio.file.Path;

public final class ArgumentParser {

    private boolean help;
    private boolean decrypt;
    private boolean encrypt;
    private Path outPath;

    public static ArgumentParser parse(String[] args) {
        ArgumentParser parsed = new ArgumentParser();
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--help", "-h" -> parsed.help = true;
                case "--decrypt" -> parsed.decrypt = true;
                case "--encrypt" -> parsed.encrypt = true;
                case "--out" -> {
                    if (i + 1 >= args.length) {
                        throw new IllegalArgumentException("--out requires a path argument");
                    }
                    parsed.outPath = Path.of(args[++i]);
                }
                default -> throw new IllegalArgumentException("unknown argument: " + args[i]);
            }
        }
        return parsed;
    }

    public boolean isHelp() {
        return help;
    }

    public boolean isDecrypt() {
        return decrypt;
    }

    public boolean isEncrypt() {
        return encrypt;
    }

    public Path getOutPath() {
        return outPath;
    }
}
