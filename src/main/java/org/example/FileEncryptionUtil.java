package org.example;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Scanner;

/**
 * Utility class for standalone file encryption/decryption operations
 * Can be used independently of the main client
 */
public class FileEncryptionUtil {
    // Encryption related constants
    private static final String ENCRYPTION_ALGORITHM = "AES";
    private static final String KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int KEY_LENGTH = 256;
    private static final int ITERATION_COUNT = 65536;
    private static final byte[] SALT = "SFTSecureSalt".getBytes(StandardCharsets.UTF_8);

    private static final Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) {
        System.out.println("=== Secure File Transfer - File Encryption Utility ===");

        if (args.length > 0) {
            //command line mode
            processCommandLine(args);
        } else {
            //interactive mode
            displayMenu();
        }
    }

    private static void displayMenu() {
        while (true) {
            System.out.println("\nSelect an option:");
            System.out.println("1. Encrypt a file");
            System.out.println("2. Decrypt a file");
            System.out.println("0. Exit");
            System.out.print("Your choice: ");

            int choice;
            try {
                choice = Integer.parseInt(scanner.nextLine().trim());
            } catch (NumberFormatException e) {
                System.out.println("Invalid input. Please enter a number.");
                continue;
            }

            switch (choice) {
                case 0:
                    System.out.println("Exiting...");
                    return;
                case 1:
                    encryptFile();
                    break;
                case 2:
                    decryptFile();
                    break;
                default:
                    System.out.println("Invalid option. Please try again.");
            }
        }
    }

    private static void processCommandLine(String[] args) {
        if (args.length < 3) {
            System.out.println("Usage: java FileEncryptionUtil [encrypt|decrypt] <inputFile> <outputFile> [password]");
            return;
        }

        String mode = args[0].toLowerCase();
        String inputFile = args[1];
        String outputFile = args[2];
        String password = args.length > 3 ? args[3] : null;

        if (password == null) {
            System.out.print("Enter password: ");
            password = scanner.nextLine();
        }

        try {
            if ("encrypt".equals(mode)) {
                encryptFile(inputFile, outputFile, password);
                System.out.println("File encrypted successfully");
            } else if ("decrypt".equals(mode)) {
                decryptFile(inputFile, outputFile, password);
                System.out.println("File decrypted successfully");
            } else {
                System.out.println("Invalid mode. Use 'encrypt' or 'decrypt'");
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }

    private static void encryptFile() {
        try {
            System.out.print("Enter input file path: ");
            String inputPath = scanner.nextLine().trim();

            System.out.print("Enter output file path (leave empty for auto): ");
            String outputPath = scanner.nextLine().trim();
            if (outputPath.isEmpty()) {
                outputPath = inputPath + ".enc";
            }

            System.out.print("Enter encryption password: ");
            String password = scanner.nextLine();

            encryptFile(inputPath, outputPath, password);
            System.out.println("File encrypted successfully to: " + outputPath);

        } catch (Exception e) {
            System.err.println("Encryption failed: " + e.getMessage());
        }
    }

    private static void decryptFile() {
        try {
            System.out.print("Enter encrypted file path: ");
            String inputPath = scanner.nextLine().trim();

            System.out.print("Enter output file path (leave empty for auto): ");
            String outputPath = scanner.nextLine().trim();
            if (outputPath.isEmpty()) {
                outputPath = inputPath.endsWith(".enc") ?
                        inputPath.substring(0, inputPath.length() - 4) :
                        inputPath + ".dec";
            }

            System.out.print("Enter decryption password: ");
            String password = scanner.nextLine();

            decryptFile(inputPath, outputPath, password);
            System.out.println("File decrypted successfully to: " + outputPath);

        } catch (Exception e) {
            System.err.println("Decryption failed: " + e.getMessage());
        }
    }

    public static void encryptFile(String inputPath, String outputPath, String password) throws Exception {
        Path input = Paths.get(inputPath);
        Path output = Paths.get(outputPath);

        if (!Files.exists(input)) {
            throw new FileNotFoundException("Input file does not exist: " + inputPath);
        }

        byte[] fileData = Files.readAllBytes(input);
        byte[] encryptedData = encryptData(fileData, password);

        Files.write(output, encryptedData);
    }

    public static void decryptFile(String inputPath, String outputPath, String password) throws Exception {
        Path input = Paths.get(inputPath);
        Path output = Paths.get(outputPath);

        if (!Files.exists(input)) {
            throw new FileNotFoundException("Input file does not exist: " + inputPath);
        }

        byte[] encryptedData = Files.readAllBytes(input);
        byte[] decryptedData = decryptData(encryptedData, password);

        Files.write(output, decryptedData);
    }

    public static byte[] encryptData(byte[] data, String password) throws Exception {
        // Generate key from password
        SecretKey key = generateKeyFromPassword(password);

        // Initialize cipher
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);

        // Encrypt the data
        return cipher.doFinal(data);
    }

    public static byte[] decryptData(byte[] encryptedData, String password) throws Exception {
        // Generate key from password
        SecretKey key = generateKeyFromPassword(password);

        // Initialize cipher
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);

        // Decrypt the data
        return cipher.doFinal(encryptedData);
    }

    private static SecretKey generateKeyFromPassword(String password) throws Exception {
        // Use PBKDF2 to derive a key from the password
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM);
        KeySpec spec = new PBEKeySpec(password.toCharArray(), SALT, ITERATION_COUNT, KEY_LENGTH);
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, ENCRYPTION_ALGORITHM);
    }

    public static String hashString(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            return Base64.getEncoder().encodeToString(input.getBytes());
        }
    }
}