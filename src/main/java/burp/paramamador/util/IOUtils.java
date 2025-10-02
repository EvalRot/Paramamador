package burp.paramamador.util;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public final class IOUtils {
    private IOUtils() {}

    public static void ensureDir(Path dir) throws IOException {
        if (dir == null) return;
        if (!Files.exists(dir)) {
            Files.createDirectories(dir);
        }
    }

    public static void writeString(Path file, String data) throws IOException {
        Files.createDirectories(file.getParent());
        Files.writeString(file, data, StandardCharsets.UTF_8);
    }
}

