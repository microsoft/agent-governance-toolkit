// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package com.microsoft.agentgovernance.acs;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Locale;

/**
 * Finds the native library {@code agent_control_specification} built from {@code policy-engine/sdk/rust} with
 * {@code cargo build --release -p agent_control_specification --features opa,bundled-dispatchers}.
 *
 * <p>The first of these that exists wins:
 * <ol>
 *   <li>the system property {@value #PROPERTY} (a file path);</li>
 *   <li>the environment variable {@value #ENVIRONMENT} (a file path);</li>
 *   <li>the resource {@code /native/<os>-<arch>/<library file>} inside the jar (copied to a temporary file);</li>
 *   <li>the library name itself, left to the operating system loader (the {@code PATH}, {@code LD_LIBRARY_PATH}, ...).</li>
 * </ol>
 */
final class NativeLibrary {

    static final String PROPERTY = "acs.native.library";
    static final String ENVIRONMENT = "ACS_NATIVE_LIBRARY";
    static final String BASE_NAME = "agent_control_specification";

    private NativeLibrary() {
    }

    /** A file to load, or the bare library name for the operating system loader. */
    record Location(Path file, String name) {
        boolean isFile() {
            return file != null;
        }

        @Override
        public String toString() {
            return isFile() ? file.toString() : name;
        }
    }

    static Location locate() {
        String explicit = System.getProperty(PROPERTY);
        if (explicit == null || explicit.isBlank()) {
            explicit = System.getenv(ENVIRONMENT);
        }
        if (explicit != null && !explicit.isBlank()) {
            Path path = Path.of(explicit.strip());
            if (!Files.isRegularFile(path)) {
                throw new AcsException("The native library named by " + PROPERTY + " / " + ENVIRONMENT + " does not exist: " + path);
            }
            return new Location(path.toAbsolutePath(), null);
        }
        String fileName = System.mapLibraryName(BASE_NAME);
        Path extracted = extractFromJar(fileName);
        if (extracted != null) {
            return new Location(extracted, null);
        }
        return new Location(null, fileName);
    }

    /** {@code windows-x86_64}, {@code linux-aarch64}, {@code macos-aarch64}, ... */
    static String platform() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        String arch = System.getProperty("os.arch", "").toLowerCase(Locale.ROOT);
        String osName = os.contains("win") ? "windows" : os.contains("mac") || os.contains("darwin") ? "macos" : "linux";
        String archName = arch.equals("amd64") || arch.equals("x86_64") ? "x86_64" : arch.equals("aarch64") || arch.equals("arm64") ? "aarch64" : arch;
        return osName + "-" + archName;
    }

    private static Path extractFromJar(String fileName) {
        String resource = "/native/" + platform() + "/" + fileName;
        try (InputStream in = NativeLibrary.class.getResourceAsStream(resource)) {
            if (in == null) {
                return null;
            }
            Path dir = Files.createTempDirectory("acs-native-");
            Path target = dir.resolve(fileName);
            Files.copy(in, target, StandardCopyOption.REPLACE_EXISTING);
            target.toFile().deleteOnExit();
            dir.toFile().deleteOnExit();
            return target;
        } catch (IOException e) {
            throw new AcsException("Cannot extract the native library " + resource + " from the jar: " + e.getMessage(), e);
        }
    }
}
