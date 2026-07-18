# shellcheck shell=sh
# JVM image workload (issue #224 jvm profile), run in the guest via
# `/bin/sh -c`: javac-compile a small program, then run it exercising
# collections, file I/O, a SHA-256 digest, an 8-thread pool, and a subprocess
# (the futex/clock_gettime-heavy signature). The program prints the sentinel
# token itself on success. POSIX sh (dash). eclipse-temurin is Ubuntu-based, so
# this also proves the setuid/setgid unpack degrade on a shadow-suite image.
set -e

d=/tmp/jvmwork
rm -rf "$d"
mkdir -p "$d"
cd "$d"
cat > Main.java <<'EOF'
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.*;

public class Main {
    static String sha256(byte[] b) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] d = md.digest(b);
        StringBuilder sb = new StringBuilder();
        for (byte x : d) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {
        // Collections.
        Map<Integer, Integer> m = new HashMap<>();
        for (int i = 0; i < 1000; i++) m.put(i, i * i);
        long collSum = 0;
        for (int v : m.values()) collSum += v;

        // File I/O + digest.
        Path p = Paths.get("/tmp/jvmwork/data.bin");
        byte[] payload = new byte[65536];
        for (int i = 0; i < payload.length; i++) payload[i] = (byte) (i & 0xff);
        Files.write(p, payload);
        byte[] back = Files.readAllBytes(p);
        if (!Arrays.equals(payload, back)) {
            System.err.println("file io mismatch");
            System.exit(1);
        }
        String digest = sha256(back);

        // 8 worker threads.
        ExecutorService ex = Executors.newFixedThreadPool(8);
        List<Future<Integer>> fs = new ArrayList<>();
        for (int t = 0; t < 8; t++) {
            final int base = t;
            fs.add(ex.submit(() -> {
                int s = 0;
                for (int i = 0; i < 100000; i++) s += (base + i) & 7;
                return s;
            }));
        }
        long threadSum = 0;
        for (Future<Integer> f : fs) threadSum += f.get();
        ex.shutdown();

        // Subprocess.
        Process pr = new ProcessBuilder("/bin/echo", "child-ok")
                .redirectErrorStream(true).start();
        String childOut = new String(pr.getInputStream().readAllBytes()).trim();
        int rc = pr.waitFor();
        if (rc != 0 || !childOut.equals("child-ok")) {
            System.err.println("subprocess failed: " + childOut);
            System.exit(1);
        }

        if (collSum <= 0 || threadSum <= 0 || digest.length() != 64) {
            System.err.println("sanity failed");
            System.exit(1);
        }
        System.out.println("elfuse-oci-jvm-workload-ok");
    }
}
EOF

javac Main.java
java Main
