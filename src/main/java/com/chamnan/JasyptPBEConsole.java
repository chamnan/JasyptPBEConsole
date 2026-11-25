package com.chamnan;

import org.jasypt.encryption.pbe.PooledPBEStringEncryptor;
import org.jasypt.encryption.pbe.config.SimpleStringPBEConfig;

import org.jline.reader.EndOfFileException;
import org.jline.reader.LineReader;
import org.jline.reader.LineReaderBuilder;
import org.jline.reader.UserInterruptException;
import org.jline.reader.impl.DefaultParser;
import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Interactive console application for string encryption and decryption
 * using Password-Based Encryption. Compatible with the encryptor
 * produced by jasypt-spring-boot-starter (PooledPBEStringEncryptor).
 *
 * <p>Build: {@code mvn clean package}
 *
 * <p>Usage: {@code java -jar target/jasypt-pbe-console-1.0.0.jar [password=xxx] [algorithm=xxx] [iterations=xxx] [iv=random|none]}
 *   <br>All flags are optional and can appear in any order. Argument values may contain {@code ${ENV_VAR}}
 *   placeholders, which are resolved against environment variables at runtime (e.g.
 *   {@code password=${ENV_VAR_PASSWORD}}). If the password is empty or a placeholder cannot be
 *   resolved, the user is prompted for input.
 *
 * <p>Defaults: algorithm=PBEWithMD5AndDES (Password-Based Encryption), iterations=1000
 *   <br>If {@code iv} is not set, encryption uses a random IV and decryption tries both
 *   {@code iv=none} and {@code iv=random}, printing both results. Values encrypted by
 *   jasypt 1.x / jasypt-spring-boot 2.x used no IV.
 */
public class JasyptPBEConsole {

    private static final String DEFAULT_ALGORITHM = "PBEWithMD5AndDES";
    private static final int DEFAULT_ITERATIONS = 1000;
    private static final String IV_NONE = "none";
    private static final String IV_RANDOM = "random";
    private static final Pattern PLACEHOLDER_PATTERN = Pattern.compile("\\$\\{([^}]+)}");

    /** Hides typed characters entirely (JLine shows nothing for a zero mask). */
    private static final Character NO_ECHO = 0;

    public static void main(String[] args) throws IOException {
        String password;
        String algorithm = DEFAULT_ALGORITHM;
        int iterations = DEFAULT_ITERATIONS;
        String iv = null; // null = not set: encrypt with random, decrypt with both

        password = null;

        for (String arg : args) {
            if (arg.startsWith("password=")) {
                password = resolvePlaceholders(arg.substring("password=".length()));
            } else if (arg.startsWith("algorithm=")) {
                algorithm = resolvePlaceholders(arg.substring("algorithm=".length()));
            } else if (arg.startsWith("iterations=")) {
                try {
                    iterations = Integer.parseInt(resolvePlaceholders(arg.substring("iterations=".length())));
                } catch (NumberFormatException e) {
                    System.err.println("Invalid iterations value. Using default: " + DEFAULT_ITERATIONS);
                }
            } else if (arg.startsWith("iv=")) {
                String value = resolvePlaceholders(arg.substring("iv=".length())).trim().toLowerCase();
                if (value.equals(IV_RANDOM) || value.equals(IV_NONE)) {
                    iv = value;
                } else {
                    System.err.println("Invalid iv value (expected random or none). "
                            + "Ignoring it: decryption will try both.");
                }
            } else {
                System.err.println("Unknown argument: " + arg);
            }
        }

        // Dynamic fallback: if no password was given, or a ${ENV_VAR} placeholder
        // could not be resolved, prompt the user for input.
        try (Terminal terminal = TerminalBuilder.builder().system(true).dumb(true).build()) {
            LineReader reader = buildReader(terminal);
            try {
                if (password == null || password.isEmpty() || hasUnresolvedPlaceholder(password)) {
                    password = reader.readLine("Enter encryption password: ", NO_ECHO);
                }
                run(password, algorithm, iterations, iv, reader);
            } catch (EndOfFileException | UserInterruptException e) {
                // Ctrl-D / Ctrl-C / end of piped input
                System.out.println();
                System.out.println("Goodbye!");
            }
        }
    }

    /**
     * Reads lines with JLine, which puts the terminal in raw mode. A plain
     * {@code Scanner(System.in)} reads through the tty's canonical mode, which on
     * macOS caps a line at 1024 bytes (MAX_CANON): a longer pasted value cannot be
     * submitted and the app appears to hang.
     */
    private static LineReader buildReader(Terminal terminal) {
        // Return input exactly as typed: no multi-line continuation on quotes or a trailing backslash.
        DefaultParser parser = new DefaultParser();
        parser.setEofOnUnclosedQuote(false);
        parser.setEofOnEscapedNewLine(false);
        return LineReaderBuilder.builder()
                .terminal(terminal)
                .parser(parser)
                .option(LineReader.Option.DISABLE_EVENT_EXPANSION, true) // keep '!' literal
                .option(LineReader.Option.INSERT_TAB, true)
                .option(LineReader.Option.HISTORY_IGNORE_SPACE, false)
                .variable(LineReader.HISTORY_SIZE, 0) // don't keep plaintext/ciphertext in memory
                .build();
    }

    private static void run(String password, String algorithm, int iterations, String iv, LineReader reader) {

        // Encrypt with the chosen IV mode (random if not set). Decrypt with the chosen
        // mode, or with both modes if not set, since a value from jasypt 1.x /
        // jasypt-spring-boot 2.x (no IV) decrypts to garbage with a random IV and vice versa.
        PooledPBEStringEncryptor encryptor =
                buildEncryptor(password, algorithm, iterations, iv != null ? iv : IV_RANDOM);
        Map<String, PooledPBEStringEncryptor> decryptors = new LinkedHashMap<>();
        if (iv != null) {
            decryptors.put(iv, encryptor);
        } else {
            decryptors.put(IV_NONE, buildEncryptor(password, algorithm, iterations, IV_NONE));
            decryptors.put(IV_RANDOM, encryptor);
        }

        System.out.println("=== Jasypt Password-Based Encryption Console ===");
        System.out.println("Algorithm : " + algorithm);
        System.out.println("Iterations: " + iterations);
        System.out.println("IV        : " + (iv != null ? iv : "not set (encrypt: random, decrypt: none + random)"));
        System.out.println("==========================================");

        runInteractiveLoop(encryptor, decryptors, reader);
    }

    /**
     * Builds an encryptor the same way jasypt-spring-boot-starter does.
     */
    private static PooledPBEStringEncryptor buildEncryptor(String password, String algorithm,
                                                           int iterations, String iv) {
        PooledPBEStringEncryptor encryptor = new PooledPBEStringEncryptor();
        SimpleStringPBEConfig config = new SimpleStringPBEConfig();
        config.setPassword(password);
        config.setAlgorithm(algorithm);
        config.setKeyObtentionIterations(String.valueOf(iterations));
        config.setPoolSize("1");
        config.setSaltGeneratorClassName("org.jasypt.salt.RandomSaltGenerator");
        config.setIvGeneratorClassName(IV_NONE.equals(iv)
                ? "org.jasypt.iv.NoIvGenerator"
                : "org.jasypt.iv.RandomIvGenerator");
        config.setStringOutputType("base64");
        encryptor.setConfig(config);
        return encryptor;
    }

    private static void runInteractiveLoop(PooledPBEStringEncryptor encryptor,
                                           Map<String, PooledPBEStringEncryptor> decryptors,
                                           LineReader reader) {

        while (true) {
            System.out.println();
            System.out.println("Choose an option:");
            System.out.println("  1. Encrypt a string");
            System.out.println("  2. Decrypt a string (raw or ENC(Base64))");
            System.out.println("  3. Exit");

            String choice = reader.readLine("> ").trim();

            switch (choice) {
                case "1" -> doEncrypt(encryptor, reader);
                case "2" -> doDecrypt(decryptors, reader);
                case "3" -> {
                    System.out.println("Goodbye!");
                    return;
                }
                default -> System.out.println("Invalid option. Please choose 1, 2, or 3.");
            }
        }
    }

    /**
     * Resolves {@code ${ENV_VAR}} placeholders against environment variables.
     * Unresolvable placeholders are left verbatim so callers can detect them.
     */
    private static String resolvePlaceholders(String value) {
        if (value == null || value.isEmpty()) {
            return value;
        }
        Matcher matcher = PLACEHOLDER_PATTERN.matcher(value);
        StringBuffer sb = new StringBuffer();
        while (matcher.find()) {
            String envValue = System.getenv(matcher.group(1));
            String replacement = envValue != null ? envValue : matcher.group(0);
            matcher.appendReplacement(sb, Matcher.quoteReplacement(replacement));
        }
        matcher.appendTail(sb);
        return sb.toString();
    }

    /**
     * Returns true if the value still contains an unresolved {@code ${ENV_VAR}} placeholder.
     */
    private static boolean hasUnresolvedPlaceholder(String value) {
        return value != null && PLACEHOLDER_PATTERN.matcher(value).find();
    }

    private static void doEncrypt(PooledPBEStringEncryptor encryptor, LineReader reader) {
        String plainText = reader.readLine("Enter string to encrypt: ");

        try {
            String encrypted = encryptor.encrypt(plainText);

            System.out.println();
            System.out.println("--- Encrypted ---");
            System.out.println("Raw : " + encrypted);
            System.out.println("ENC : ENC(" + encrypted + ")");
            System.out.println("-----------------");
        } catch (Exception e) {
            System.err.println("Encryption error: " + e.getMessage());
        }
    }

    private static void doDecrypt(Map<String, PooledPBEStringEncryptor> decryptors, LineReader reader) {
        String input = reader.readLine("Enter ciphertext (raw Base64 or ENC(Base64)): ").trim();

        // Strip ENC() wrapper if present
        String encrypted = unwrapENC(input);

        if (decryptors.size() == 1) {
            try {
                String plainText = decryptors.values().iterator().next().decrypt(encrypted);
                System.out.println();
                System.out.println("--- Decrypted ---");
                System.out.println(plainText);
                System.out.println("-----------------");
            } catch (Exception e) {
                System.err.println("Decryption error: " + describeError(e));
            }
            return;
        }

        // iv not set: show the result of every IV mode. Only one is correct; the other
        // either fails or yields garbled text.
        System.out.println();
        System.out.println("--- Decrypted ---");
        int succeeded = 0;
        for (Map.Entry<String, PooledPBEStringEncryptor> entry : decryptors.entrySet()) {
            String label = String.format("iv=%-6s : ", entry.getKey());
            try {
                System.out.println(label + entry.getValue().decrypt(encrypted));
                succeeded++;
            } catch (Exception e) {
                System.out.println(label + "(failed) " + describeError(e));
            }
        }
        System.out.println("-----------------");
        if (succeeded > 1) {
            System.out.println("Only one result is correct; the other is garbled text.");
        }
    }

    private static String describeError(Exception e) {
        String msg = e.getMessage();
        if (msg == null || msg.isBlank()) {
            return "Input is not a valid encrypted string "
                    + "(wrong password, wrong format, or not encrypted with this configuration).";
        }
        return msg;
    }

    /**
     * Strips the ENC() wrapper from a ciphertext if present.
     * Accepts both raw Base64 and {@code ENC(Base64)} formats.
     */
    private static String unwrapENC(String input) {
        if (input.startsWith("ENC(") && input.endsWith(")")) {
            return input.substring(4, input.length() - 1);
        }
        return input;
    }

}
