package de.dhbw.ctf;

import java.io.InputStream;
import java.lang.reflect.Method;

// Einstiegspunkt (JAR-Manifest: Main-Class). Main lädt Crypto niemals per
// normalem "import"/Compile-Zeit-Referenz, sondern ausschließlich über den
// EncryptedClassLoader + Reflection (siehe main() unten) — das verhindert,
// dass ein Standard-Decompiler den Aufruf klar als "Main benutzt Crypto"
// anzeigt, und erzwingt, dass Crypto erst entschlüsselt werden muss, bevor
// irgendeine seiner Methoden aufrufbar ist.
public class Main {

    // Klassenname "de.dhbw.ctf.Crypto", byteweise mit 0x5A ge-XOR-t, damit
    // er nicht im Klartext im Konstanten-Pool steht (z.B. `strings vault.jar`
    // würde ihn sonst direkt zeigen). Wird von _s() zur Laufzeit dekodiert.
    private static final byte[] _C = {0x3e,0x3f,0x74,0x3e,0x32,0x38,0x2d,0x74,0x39,0x2e,0x3c,0x74,0x19,0x28,0x23,0x2a,0x2e,0x35};

    // Methodennamen von Crypto, einzeln XOR 0x5A kodiert (a,b,c,d,e,f) —
    // damit dieselbe Verschleierung wie bei _C auch für die per Reflection
    // aufgerufenen Methodennamen gilt. Reihenfolge entspricht Crypto:
    // a=computeMac, b=extractRole, c=getFlag, d=getSampleMessage,
    // e=getSampleMac, f=getSecretLength (im CLI-Pfad nie aufgerufen).
    private static final byte[] _Ma = {0x3b};
    private static final byte[] _Mb = {0x38};
    private static final byte[] _Mc = {0x39};
    private static final byte[] _Md = {0x3e};
    private static final byte[] _Me = {0x3f};
    private static final byte[] _Mf = {0x3c};

    // Wie _s(), aber mit wählbarem XOR-Schlüssel statt fest 0x5A — Grundlage
    // für _resolveMethod()/_resolveClass() unten, die pro Kandidat einen
    // anderen Schlüssel probieren, statt nur einen Klartext zu kennen.
    private static String _sx(byte[] b, byte key) {
        byte[] r = new byte[b.length];
        for (int i = 0; i < b.length; i++) r[i] = (byte) (b[i] ^ key);
        return new String(r, java.nio.charset.StandardCharsets.UTF_8);
    }

    // Kehrt die XOR-0x5A-Kodierung von _C/_Ma.._Mf wieder in Klartext um.
    private static String _s(byte[] b) {
        return _sx(b, (byte) 0x5A);
    }

    // Ein Kandidat ist ein (Byte-Array, Schlüssel)-Paar. Pro Aufrufstelle
    // gibt es mehrere Kandidaten, von denen nur einer den echten Methoden-
    // /Klassennamen ergibt (Schlüssel 0x5A) — die übrigen dekodieren zu
    // Zeichen, die keine echte Methode/Klasse treffen und daher eine
    // NoSuchMethodException/ClassNotFoundException auslösen. Ein statischer
    // Reader sieht nur eine Liste plausibler XOR-Blobs; welcher davon der
    // "richtige" ist, ergibt sich erst beim Ausführen der try/catch-Kette
    // zur Laufzeit — nicht mehr durch einmaliges Auswerten einer einzigen
    // globalen XOR-Formel wie bisher bei _s().
    private static final class _Cand {
        final byte[] data;
        final byte key;
        _Cand(byte[] data, int key) { this.data = data; this.key = (byte) key; }
    }

    // Klassenname "de.dhbw.ctf.Crypto" als Kandidatenliste: Schlüssel 0x5A
    // ist der echte (siehe _C-Kommentar oben, unverändert), 0x71 und 0x3C
    // sind Lockvogel-Schlüssel, die auf denselben Rohbytes eine ungültige
    // Zeichenkette ergeben und daher in loadClass() zuverlässig eine
    // ClassNotFoundException auslösen.
    private static final _Cand[] _CCand = {
        new _Cand(_C, 0x71),
        new _Cand(_C, 0x5A), // echter Schlüssel -> "de.dhbw.ctf.Crypto"
        new _Cand(_C, 0x3C),
    };

    // Methodennamen von Crypto als Kandidatenlisten. Jede Liste enthält
    // denselben kodierten Rohbyte-Wert mit drei Schlüsseln; nur 0x5A trifft
    // den echten Buchstaben (a,b,c,d,e). f=getSecretLength bleibt
    // unverändert (im CLI-Pfad nie aufgerufen, daher keine Kandidatenliste
    // nötig).
    private static final _Cand[] _MaCand = { new _Cand(_Ma, 0x19), new _Cand(_Ma, 0x5A), new _Cand(_Ma, 0x66) };
    private static final _Cand[] _MbCand = { new _Cand(_Mb, 0x0D), new _Cand(_Mb, 0x5A), new _Cand(_Mb, 0x77) };
    private static final _Cand[] _McCand = { new _Cand(_Mc, 0x12), new _Cand(_Mc, 0x5A), new _Cand(_Mc, 0x64) };
    private static final _Cand[] _MdCand = { new _Cand(_Md, 0x1B), new _Cand(_Md, 0x5A), new _Cand(_Md, 0x68) };
    private static final _Cand[] _MeCand = { new _Cand(_Me, 0x0A), new _Cand(_Me, 0x5A), new _Cand(_Me, 0x73) };

    // g=verifyDigestFormat (sekundäre Konsistenzprüfung, siehe Crypto.g()
    // und deren Aufruf in main() unten). Folgt demselben XOR-0x5A-Schema
    // wie a..f: 'g' (0x67) ^ 0x5A = 0x3D.
    private static final byte[] _Mg = {0x3d};
    private static final _Cand[] _MgCand = { new _Cand(_Mg, 0x44), new _Cand(_Mg, 0x5A), new _Cand(_Mg, 0x08) };

    // Versucht die Kandidaten der Reihe nach per getMethod() aufzulösen und
    // gibt die erste erfolgreich gefundene Method zurück. Bricht erst mit
    // der letzten NoSuchMethodException ab, wenn kein Kandidat passt —
    // dieselbe Fehlersemantik wie ein direkter getMethod()-Aufruf.
    private static Method _resolveMethod(Class<?> c, _Cand[] candidates, Class<?>... paramTypes)
            throws NoSuchMethodException {
        NoSuchMethodException last = null;
        for (_Cand cand : candidates) {
            String name = _sx(cand.data, cand.key);
            try {
                return c.getMethod(name, paramTypes);
            } catch (NoSuchMethodException e) {
                last = e;
            }
        }
        throw last;
    }

    // Analog zu _resolveMethod(), aber für den Klassennamen selbst
    // (loader.loadClass(...)) — nur ein Kandidat decodiert zu
    // "de.dhbw.ctf.Crypto", die anderen laufen bewusst in eine
    // ClassNotFoundException.
    private static Class<?> _resolveClass(ClassLoader loader, _Cand[] candidates) throws ClassNotFoundException {
        ClassNotFoundException last = null;
        for (_Cand cand : candidates) {
            String name = _sx(cand.data, cand.key);
            try {
                return loader.loadClass(name);
            } catch (ClassNotFoundException e) {
                last = e;
            }
        }
        throw last;
    }

    // Eigener ClassLoader, der KEINE normale .class-Datei aus dem JAR
    // lädt, sondern <name>.class.encrypted liest, sie mit _d()/_key()
    // entschlüsselt und das Ergebnis per defineClass() direkt der JVM
    // übergibt. Das ist die "Verschlüsselung", die Crypto.class im JAR
    // versteckt (in Wahrheit reversibles Byte-Reverse+XOR ohne echtes
    // Geheimnis-Derivat, siehe _d() unten — die Sicherheit hängt allein
    // daran, wie schwer _key() zu rekonstruieren ist).
    //
    // Public (nicht paketsichtbar), da Crypto._secret() _key() aufruft,
    // nachdem Crypto selbst schon über diesen Loader geladen wurde —
    // Zugriffe über Loader-Grenzen hinweg zählen als unterschiedliche
    // Runtime-Packages, auch bei gleichem Java-Package-Namen.
    public static class EncryptedClassLoader extends ClassLoader {

        public EncryptedClassLoader(ClassLoader parent) { super(parent); }

        // Wird von der JVM aufgerufen, wenn loadClass() die angeforderte
        // Klasse nicht bereits über den Eltern-ClassLoader findet.
        @Override
        protected Class<?> findClass(String name) throws ClassNotFoundException {
            String path = name.replace('.', '/') + ".class.encrypted";
            try (InputStream in = getResourceAsStream(path)) {
                if (in == null) throw new ClassNotFoundException(path);
                byte[] data = in.readAllBytes();
                byte[] dec  = _d(data, _key());
                return defineClass(name, dec, 0, dec.length);
            } catch (ClassNotFoundException e) {
                throw e;
            } catch (Exception e) {
                throw new ClassNotFoundException(name, e);
            }
        }

        // Lokaler Anteil des Schlüssels.
        private static final int _K1 = 0x2C;

        // Der vollständige Schlüssel setzt sich aus vier getrennt liegenden
        // Anteilen zusammen: dieser Konstante, einem Manifest-Attribut
        // (build.sh setzt es beim Packen), VersionInfo.BUILD_TAG und
        // RuntimeTag.SESSION_TAG. Statt die Anteile nur zu XOR-en, werden
        // sie über SHA-256 zu einem Schlüssel verdichtet — wer nicht alle
        // vier Fragmente korrekt kombiniert, bekommt einen komplett
        // anderen Schlüssel, kein teilweise entschlüsseltes Ergebnis.
        // Public (nicht private), da Crypto._secret() diesen Wert ebenfalls
        // einbezieht (siehe dort) — koppelt die beiden separat
        // verschleierten Klassen, statt sie unabhängig lösbar zu lassen.
        // ProGuard behandelt Member paketsichtbarer Library-Klassen sonst
        // als nicht referenzierbar (siehe crypto.pro).
        public static int _key() {
            int k2 = _manifestTag();
            int k3 = VersionInfo.BUILD_TAG;
            int k4 = RuntimeTag.SESSION_TAG;
            return _deriveKey(_K1, k2, k3, k4);
        }

        // Public aus demselben Grund wie _key() oben: Crypto._secret()
        // ruft dies direkt auf.
        public static int _deriveKey(int a, int b, int c, int d) {
            try {
                java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
                java.nio.ByteBuffer buf = java.nio.ByteBuffer.allocate(16);
                buf.putInt(a).putInt(b).putInt(c).putInt(d);
                byte[] hash = md.digest(buf.array());
                return ((hash[0] & 0xFF) << 24) | ((hash[1] & 0xFF) << 16)
                     | ((hash[2] & 0xFF) << 8)  |  (hash[3] & 0xFF);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        private static int _manifestTag() {
            try (InputStream in = EncryptedClassLoader.class.getClassLoader()
                    .getResourceAsStream("META-INF/MANIFEST.MF")) {
                if (in == null) throw new IllegalStateException("manifest missing");
                java.util.jar.Manifest mf = new java.util.jar.Manifest(in);
                String v = mf.getMainAttributes().getValue("X-Build-Tag");
                if (v == null) throw new IllegalStateException("X-Build-Tag missing");
                return Integer.parseInt(v.trim());
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        // "Entschlüsselung" von Crypto.class.encrypted: Array-Reverse
        // (Byte i <-> Byte n-1-i) kombiniert mit XOR(key) auf jedem Byte.
        // Selbstinvers — _d(_d(x,k),k) == x — build.sh nutzt exakt dieselbe
        // Operation, um die Klartext-Klasse vor dem Packen zu "verschlüsseln".
        // Keine echte Kryptografie: ohne Ableitung aus einem echten Geheimnis
        // ist das reversibel, sobald key bekannt ist (siehe _key() oben).
        private static byte[] _d(byte[] data, int key) {
            byte[] r = data.clone();
            int n = r.length;
            for (int i = 0; i < n / 2; i++) {
                byte a = r[i];
                byte b = r[n - 1 - i];
                r[i]         = (byte) ((b ^ key) & 0xFF);
                r[n - 1 - i] = (byte) ((a ^ key) & 0xFF);
            }
            if (n % 2 == 1) r[n / 2] = (byte) ((r[n / 2] ^ key) & 0xFF);
            return r;
        }
    }

    // --- internal validation ---
    // Toter Code, wird von main() nie aufgerufen — reine Ablenkung.
    private static boolean _chk(String s) {
        if (s == null || s.length() < 4) return false;
        int acc = ~(((int) Math.PI ^ Integer.MAX_VALUE >> 16) + Short.MAX_VALUE);
        for (int i = 0; i < s.length(); i++) acc ^= (s.charAt(i) << (i % 8));
        return (acc & 0xDEAD) == 0xBEEF;
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 0 || args[0].equals("--help") || args[0].equals("-h")) {
            printHelp();
            return;
        }

        // Löst Crypto ausschließlich über den EncryptedClassLoader auf —
        // die JVM kennt die Klasse vor diesem Punkt nicht, defineClass()
        // im Loader macht sie erst hier verfügbar.
        EncryptedClassLoader loader = new EncryptedClassLoader(Main.class.getClassLoader());
        Class<?> crypto = _resolveClass(loader, _CCand);

        // --sample: gibt eine gültige Beispiel-Nachricht + ihren MAC aus,
        // ohne Rollenprüfung — Ausgangspunkt für den Length-Extension-Angriff.
        if (args[0].equals("--sample")) {
            String msg = (String) _resolveMethod(crypto, _MdCand).invoke(null);
            String mac = (String) _resolveMethod(crypto, _MeCand).invoke(null);
            System.out.println("Sample message (hex) : " + msg);
            System.out.println("Sample MAC           : " + mac);
            return;
        }

        if (args.length != 2) {
            System.err.println("Error: expected 2 arguments. Run with --help for usage.");
            System.exit(1);
        }

        String messageHex = args[0];
        String inputMac   = args[1];

        byte[] messageBytes;
        try {
            messageBytes = java.util.HexFormat.of().parseHex(messageHex);
        } catch (IllegalArgumentException e) {
            System.err.println("Error: message must be hex-encoded (e.g. 757365723d6775657374).");
            System.exit(1);
            return;
        }

        Method mComputeMac  = _resolveMethod(crypto, _MaCand, byte[].class);
        Method mExtractRole = _resolveMethod(crypto, _MbCand, byte[].class);
        Method mGetFlag     = _resolveMethod(crypto, _McCand);

        // Kernprüfung: Server berechnet den MAC selbst aus der
        // eingereichten messageBytes und vergleicht ihn mit dem
        // übergebenen. Akzeptiert JEDE Nachricht, für die der Aufrufer
        // einen passenden MAC liefert — inklusive einer per
        // Hash-Length-Extension aus der --sample-Ausgabe gefälschten.
        String expectedMac = (String) mComputeMac.invoke(null, (Object) messageBytes);

        if (!expectedMac.equalsIgnoreCase(inputMac)) {
            System.out.println("Access denied. Invalid MAC.");
            System.exit(1);
        }

        // Sekundäre Konsistenzprüfung (Digest-Form, siehe Crypto.g()) — läuft
        // auf jedem regulären Pfad nach der MAC-Prüfung, bevor die
        // Rollenprüfung beginnt.
        Method mVerifyFormat = _resolveMethod(crypto, _MgCand, byte[].class, String.class);
        boolean formatOk = (boolean) mVerifyFormat.invoke(null, (Object) messageBytes, inputMac);
        if (!formatOk) {
            System.out.println("Access denied. Integrity check failed.");
            System.exit(1);
        }

        // Rollenprüfung NACH der MAC-Prüfung: sobald der MAC passt, wird
        // b() auf dieselben messageBytes angewendet und deren letztes
        // "user="-Feld gewinnt — auch wenn diese Bytes durch Length-
        // Extension um ein zweites, gefälschtes "&user=admin" verlängert
        // wurden.
        String role = (String) mExtractRole.invoke(null, (Object) messageBytes);

        if ("admin".equals(role)) {
            System.out.println("Access granted.");
            System.out.println((String) mGetFlag.invoke(null));
        } else {
            System.out.println("Access denied. You are: " + role);
            System.exit(1);
        }
    }

    static void printHelp() {
        System.out.println("VaultAccess - Token Validator");
        System.out.println();
        System.out.println("Usage:");
        System.out.println("  java -jar vault.jar <message-hex> <mac>");
        System.out.println("  java -jar vault.jar --sample");
        System.out.println("  java -jar vault.jar --help");
        System.out.println();
        System.out.println("Arguments:");
        System.out.println("  message-hex  The access token message, hex-encoded");
        System.out.println("  mac          SHA-256 MAC for the message (hex)");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  java -jar vault.jar --sample");
        System.out.println("  java -jar vault.jar 757365723d6775657374 <mac>");
    }
}
