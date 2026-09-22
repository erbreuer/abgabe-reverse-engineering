package de.dhbw.securevault;

import de.dhbw.securevault.cli.ArgumentParser;
import de.dhbw.securevault.cli.HelpText;
import de.dhbw.securevault.loader.VaultClassLoader;

import java.lang.reflect.Method;
import java.nio.file.Path;

public class Main {

    public static void main(String[] args) {
        ArgumentParser parsed;
        try {
            parsed = ArgumentParser.parse(args);
        } catch (IllegalArgumentException e) {
            System.err.println("Fehler: " + e.getMessage());
            System.err.println();
            System.err.println(HelpText.text());
            System.exit(2);
            return;
        }

        if (parsed.isHelp() || (!parsed.isDecrypt() && !parsed.isEncrypt())) {
            System.out.println(HelpText.text());
            return;
        }

        try {
            run(parsed);
        } catch (Exception e) {
            System.err.println("Fehler beim Verarbeiten des Tresors: " + e.getMessage());
            if (System.getenv("SECUREVAULT_DEBUG") != null) {
                e.printStackTrace();
            }
            System.exit(1);
        }
    }

    private static void run(ArgumentParser parsed) throws Exception {
        VaultClassLoader loader = new VaultClassLoader(Main.class.getClassLoader());
        byte[] anchorBytes = loader.readIntegrityAnchorBytes();

        Class<?> keyAssemblerClass = Class.forName(
                "de.dhbw.securevault.keyparts.KeyAssembler", true, loader);
        Method reconstructKey = keyAssemblerClass.getDeclaredMethod(
                "reconstructKey", ClassLoader.class, byte[].class);
        byte[] key = (byte[]) reconstructKey.invoke(null, loader, anchorBytes);

        Class<?> flagStoreClass = Class.forName(
                "de.dhbw.securevault.vault.FlagStore", true, loader);
        Method runMethod = flagStoreClass.getDeclaredMethod(
                "run", String.class, byte[].class, Path.class);

        String mode = parsed.isEncrypt() ? "encrypt" : "decrypt";
        runMethod.invoke(null, mode, key, parsed.getOutPath());
    }
}
