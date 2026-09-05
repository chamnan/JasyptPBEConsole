package com.chamnan;

import org.jasypt.encryption.pbe.PooledPBEStringEncryptor;
import org.jasypt.encryption.pbe.config.SimpleStringPBEConfig;

import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Interactive console application for string encryption and decryption
 * using Password-Based Encryption. Compatible with the encryptor
 * produced by jasypt-spring-boot-starter (PooledPBEStringEncryptor).
 *
 * <p>Build: {@code mvn clean package}
 *
 * <p>Usage: {@code java -jar target/jasypt-pbe-console-1.0.0.jar [password=xxx] [algorithm=xxx] [iterations=xxx]}
 *   <br>All flags are optional and can appear in any order. Argument values may contain {@code ${ENV_VAR}}
 *   placeholders, which are resolved against environment variables at runtime (e.g.
 *   {@code password=${ENV_VAR_PASSWORD}}). If the password is empty or a placeholder cannot be
 *   resolved, the user is prompted for input.
 *
 * <p>Defaults: algorithm=PBEWithMD5AndDES (Password-Based Encryption), iterations=1000
 */
public class JasyptPBEConsole {

    private static final String DEFAULT_ALGORITHM = "PBEWithMD5AndDES";
    private static final int DEFAULT_ITERATIONS = 1000;
    private static final Pattern PLACEHOLDER_PATTERN = Pattern.compile("\\$\\{([^}]+)}");

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        String password;
        String algorithm = DEFAULT_ALGORITHM;
        int iterations = DEFAULT_ITERATIONS;

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
            } else {
                System.err.println("Unknown argument: " + arg);
            }
        }

        // Dynamic fallback: if no password was given, or a ${ENV_VAR} placeholder
        // could not be resolved, prompt the user for input.
        if (password == null || password.isEmpty() || hasUnresolvedPlaceholder(password)) {
            password = promptPassword(scanner);
        }

        // Build encryptor the same way jasypt-spring-boot-starter does
        PooledPBEStringEncryptor encryptor = new PooledPBEStringEncryptor();
        SimpleStringPBEConfig config = new SimpleStringPBEConfig();
        config.setPassword(password);
        config.setAlgorithm(algorithm);
        config.setKeyObtentionIterations(String.valueOf(iterations));
        config.setPoolSize("1");
        config.setSaltGeneratorClassName("org.jasypt.salt.RandomSaltGenerator");
        config.setIvGeneratorClassName("org.jasypt.iv.RandomIvGenerator");
        config.setStringOutputType("base64");
        encryptor.setConfig(config);

        System.out.println("=== Jasypt Password-Based Encryption Console ===");
        System.out.println("Algorithm : " + algorithm);
        System.out.println("Iterations: " + iterations);
        System.out.println("==========================================");

        runInteractiveLoop(encryptor, scanner);
    }

    private static void runInteractiveLoop(PooledPBEStringEncryptor encryptor, Scanner scanner) {

        while (true) {
            System.out.println();
            System.out.println("Choose an option:");
            System.out.println("  1. Encrypt a string");
            System.out.println("  2. Decrypt a string (raw or ENC(Base64))");
            System.out.println("  3. Exit");
            System.out.print("> ");

            String choice = scanner.nextLine().trim();

            switch (choice) {
                case "1" -> doEncrypt(encryptor, scanner);
                case "2" -> doDecrypt(encryptor, scanner);
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

    private static String promptPassword(Scanner scanner) {
        java.io.Console console = System.console();
        if (console != null) {
            char[] chars = console.readPassword("Enter encryption password: ");
            if (chars == null) {
                return "";
            }
            return new String(chars);
        }
        // Fallback if no console available (e.g., piped input or IDE)
        System.out.print("Enter encryption password: ");
        return scanner.nextLine().trim();
    }

    private static void doEncrypt(PooledPBEStringEncryptor encryptor, Scanner scanner) {
        System.out.print("Enter string to encrypt: ");
        String plainText = scanner.nextLine();

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

    private static void doDecrypt(PooledPBEStringEncryptor encryptor, Scanner scanner) {
        System.out.print("Enter ciphertext (raw Base64 or ENC(Base64)): ");
        String input = scanner.nextLine().trim();

        // Strip ENC() wrapper if present
        String encrypted = unwrapENC(input);

        try {
            String plainText = encryptor.decrypt(encrypted);

            System.out.println();
            System.out.println("--- Decrypted ---");
            System.out.println(plainText);
            System.out.println("-----------------");
        } catch (Exception e) {
            String msg = e.getMessage();
            if (msg == null || msg.isBlank()) {
                System.err.println("Decryption error: Input is not a valid encrypted string "
                        + "(wrong password, wrong format, or not encrypted with this configuration).");
            } else {
                System.err.println("Decryption error: " + msg);
            }
        }
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
