package org.example;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Scanner;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class SecureFileTransferClient {
    private static final String SERVER_ADDRESS = "212.156.136.222";
    private static final int SERVER_PORT = 5002;
    private static final String CLIENT_FOLDER = "/Users/utkusancakli/Desktop/STFC";
    private static final String DOWNLOADS_FOLDER = CLIENT_FOLDER + "/Downloads";

    private SSLSocket socket;
    private DataInputStream in;
    private DataOutputStream out;
    private String sessionToken;
    private int userId;
    private String username;
    private final Scanner scanner;
    private final ScheduledExecutorService heartbeatScheduler;

    private static final String ENCRYPTION_ALGORITHM = "AES";
    private static final String KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int KEY_LENGTH = 256;
    private static final int ITERATION_COUNT = 65536;
    private static final byte[] SALT = "SFTSecureSalt".getBytes(StandardCharsets.UTF_8);

    public SecureFileTransferClient() {
        scanner = new Scanner(System.in);
        heartbeatScheduler = Executors.newSingleThreadScheduledExecutor();
        createDirectories();
    }

    public static void main(String[] args) {
        SecureFileTransferClient client = new SecureFileTransferClient();
        try {
            client.connect();
            client.startHeartbeat();
            client.displayMainMenu();
        }
        catch (Exception e) {
            System.err.println("Fatal error: " + e.getMessage());
            e.printStackTrace();
        }
        finally {
            client.disconnect();
        }
    }

    private void createDirectories() {
        try {
            Files.createDirectories(Paths.get(CLIENT_FOLDER));
            Files.createDirectories(Paths.get(DOWNLOADS_FOLDER));
        }
        catch (IOException e) {
            System.err.println("Failed to create client directories: " + e.getMessage());
        }
    }

    public void connect() {
        try {
            //set up ssl
            KeyStore trustStore = KeyStore.getInstance("JKS");
            try (FileInputStream fis = new FileInputStream("client_truststore.jks")) {
                trustStore.load(fis, "012345".toCharArray());
            }

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), null);

            SSLSocketFactory factory = sslContext.getSocketFactory();
            socket = (SSLSocket) factory.createSocket(SERVER_ADDRESS, SERVER_PORT);
            socket.setEnabledProtocols(new String[]{"TLSv1.2", "TLSv1.3"});

            in = new DataInputStream(socket.getInputStream());
            out = new DataOutputStream(socket.getOutputStream());

            System.out.println("Connected to server successfully using TLS");

        }
        catch (Exception e) {
            System.err.println("Failed to connect to server: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    public void startHeartbeat() {
        heartbeatScheduler.scheduleAtFixedRate(() -> {
            try {
                if (sessionToken != null) {
                    sendCommand("HEARTBEAT");
                    String response = in.readUTF();
                    // System.out.println("Heartbeat response: " + response);
                }
            }
            catch (IOException e) {
                System.err.println("Heartbeat failed: " + e.getMessage());
                disconnect();
            }
        }, 30, 30, TimeUnit.SECONDS);
    }

    public void disconnect() {
        try {
            heartbeatScheduler.shutdown();
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
            System.out.println("Disconnected from server");
        }
        catch (IOException e) {
            System.err.println("Error during disconnect: " + e.getMessage());
        }
    }

    private void sendCommand(String command) throws IOException {
        // System.out.println("Sending command: " + command);
        out.writeUTF(command);
    }

    public void displayMainMenu() {
        while (true) {
            System.out.println("\n=== Secure File Transfer Client ===");
            if (sessionToken == null) {
                System.out.println("1. Register");
                System.out.println("2. Login");
            } else {
                System.out.println("1. Upload File for Sharing");
                System.out.println("2. List My Shares");
                System.out.println("3. Download Shared File");
                System.out.println("4. Delete Share");
                System.out.println("5. Search Users");
                System.out.println("6. Create Public Share Link");
                System.out.println("7. Access Share by ID");
                System.out.println("8. Logout");
            }
            System.out.println("0. Exit");
            System.out.print("Select an option: ");

            int choice;
            try {
                choice = Integer.parseInt(scanner.nextLine().trim());
            } catch (NumberFormatException e) {
                System.out.println("Invalid input. Please enter a number.");
                continue;
            }

            try {
                if (sessionToken == null) {
                    switch (choice) {
                        case 0 -> {
                            disconnect();
                            return;
                        }
                        case 1 -> register();
                        case 2 -> login();
                        default -> System.out.println("Invalid option. Please try again.");
                    }
                }
                else {
                    switch (choice) {
                        case 0 -> {
                            logout();
                            disconnect();
                            return;
                        }
                        case 1 -> uploadFile();
                        case 2 -> listShares();
                        case 3 -> downloadSharedFile();
                        case 4 -> deleteShare();
                        case 5 -> searchUsers();
                        case 6 -> createShareLink();
                        case 7 -> accessShareById();
                        case 8 -> {
                            logout();
                            System.out.println("Logged out successfully");
                        }
                        default -> System.out.println("Invalid option. Please try again.");
                    }
                }
            }
            catch (IOException e) {
                System.err.println("Error communicating with server: " + e.getMessage());
                disconnect();
                return;
            }
        }
    }

    private void register() throws IOException {
        System.out.println("\n=== User Registration ===");

        System.out.print("Enter username: ");
        String username = scanner.nextLine().trim();

        System.out.print("Enter password: ");
        String password = scanner.nextLine().trim();

        System.out.print("Enter email: ");
        String email = scanner.nextLine().trim();

        sendCommand("REGISTER");
        out.writeUTF(username);
        out.writeUTF(password);
        out.writeUTF(email);

        String response = in.readUTF();
        System.out.println("Server response: " + response);
    }

    private void login() throws IOException {
        System.out.println("\n=== Login ===");

        System.out.print("Enter username: ");
        username = scanner.nextLine().trim();

        System.out.print("Enter password: ");
        String password = scanner.nextLine().trim();

        sendCommand("LOGIN");
        out.writeUTF(username);
        out.writeUTF(password);

        String response = in.readUTF();

        if (response.equals("SUCCESS:LOGIN_OK")) {
            sessionToken = in.readUTF();
            userId = in.readInt();
            System.out.println("Login successful");
        }
        else {
            System.out.println("Login failed: " + response);
        }
    }

    private void logout() throws IOException {
        if (sessionToken != null) {
            sendCommand("LOGOUT");
            out.writeUTF(sessionToken);

            String response = in.readUTF();
            System.out.println("Server response: " + response);

            if (response.startsWith("SUCCESS")) {
                sessionToken = null;
                userId = 0;
                username = null;
            }
        }
    }

    private void uploadFile() throws IOException {
        System.out.println("\n=== Upload File for Sharing ===");

        System.out.print("Enter file path: ");
        String filePath = scanner.nextLine().trim();

        File file = new File(filePath);
        if (!file.exists() || !file.isFile()) {
            System.out.println("File not found or not a regular file");
            return;
        }

        System.out.print("Share with user (enter username or '*' for public): ");
        String recipient = scanner.nextLine().trim();

        System.out.print("Expiry time in hours: ");
        int expiryHours;
        try {
            expiryHours = Integer.parseInt(scanner.nextLine().trim());
        }
        catch (NumberFormatException e) {
            System.out.println("Invalid expiry time. Using default (24h)");
            expiryHours = 24;
        }

        System.out.print("Enter encryption password (leave empty for no encryption): ");
        String encryptionPassword = scanner.nextLine().trim();
        boolean encrypt = !encryptionPassword.isEmpty();

        String originalFilename = file.getName();
        long fileSize = file.length();

        byte[] fileData = Files.readAllBytes(file.toPath());

        if (encrypt) {
            try {
                fileData = encryptData(fileData, encryptionPassword);
                originalFilename += ".enc"; //mark encrypted files
            } catch (Exception e) {
                System.err.println("Error encrypting file: " + e.getMessage());
                return;
            }
        }

        sendCommand("UPLOAD_FOR_SHARE");
        out.writeUTF(sessionToken);
        out.writeUTF(originalFilename);
        out.writeLong(fileData.length);
        out.writeUTF(recipient);
        out.writeInt(expiryHours);

        //wait for server
        String readyResponse = in.readUTF();
        if (readyResponse.equals("READY_TO_RECEIVE")) {

            out.write(fileData);
            out.flush();

            String response = in.readUTF();
            System.out.println("Server response: " + response);

            if (response.startsWith("SUCCESS")) {
                String shareId = in.readUTF();
                System.out.println("File uploaded with Share ID: " + shareId);

                if (encrypt) {
                    saveEncryptionInfo(shareId, encryptionPassword);
                }
            }
        }
        else {
            System.out.println("Server not ready to receive: " + readyResponse);
        }
    }

    private void listShares() throws IOException {
        System.out.println("\n=== My Shares ===");

        System.out.print("Include shares shared with me? (y/n): ");
        boolean includeIncoming = scanner.nextLine().trim().toLowerCase().startsWith("y");

        sendCommand("LIST_MY_SHARES");
        out.writeUTF(sessionToken);
        out.writeBoolean(includeIncoming);

        int count = in.readInt();
        if (count == 0) {
            System.out.println("No shares found");
            return;
        }

        System.out.println("Found " + count + " shares:");
        System.out.println("----------------------------------------------------");
        System.out.printf("%-10s %-15s %-15s %-20s %-10s\n", "Share ID", "Owner", "Recipient", "Filename", "Expires");
        System.out.println("----------------------------------------------------");

        for (int i = 0; i < count; i++) {
            String shareInfo = in.readUTF();
            String[] parts = shareInfo.split("###");
            if (parts.length >= 7) {
                int ownerId = Integer.parseInt(parts[0]);
                String owner = parts[1];
                String recipient = parts[2];
                String filename = parts[3];
                String shareId = parts[4];
                long expiry = Long.parseLong(parts[6]);

                long expiryHours = (expiry - System.currentTimeMillis()) / (60 * 60 * 1000);

                System.out.printf("%-10s %-15s %-15s %-20s %-10s\n",
                        shareId.substring(0, Math.min(shareId.length(), 8)),
                        owner,
                        recipient.equals("*") ? "Public" : recipient,
                        filename,
                        expiryHours + " hours");
            }
        }
        System.out.println("----------------------------------------------------");
    }

    private void downloadSharedFile() throws IOException {
        System.out.println("\n=== Download Shared File ===");

        System.out.print("Enter Share ID: ");
        String shareId = scanner.nextLine().trim();

        sendCommand("DOWNLOAD_SHARED");
        out.writeUTF(sessionToken);
        out.writeUTF(shareId);

        String response = in.readUTF();
        if (response.equals("SUCCESS:DOWNLOAD_READY")) {
            String filename = in.readUTF();
            long fileSize = in.readLong();

            System.out.println("Downloading file: " + filename + " (" + (fileSize / 1024) + " KB)");

            //create file to save things
            String downloadPath = DOWNLOADS_FOLDER + File.separator + filename;
            Path filePath = Paths.get(downloadPath);

            byte[] fileData = new byte[(int) fileSize];
            int bytesRead = 0;
            int offset = 0;

            //read file
            while (offset < fileSize && (bytesRead = in.read(fileData, offset, (int) (fileSize - offset))) > 0) {
                offset += bytesRead;
            }

            boolean isEncrypted = filename.toLowerCase().endsWith(".enc");
            if (isEncrypted) {
                System.out.print("This file is encrypted. Enter decryption password: ");
                String password = scanner.nextLine().trim();

                try {
                    fileData = decryptData(fileData, password);
                    //remove .enc extension for decrypted file
                    downloadPath = downloadPath.substring(0, downloadPath.length() - 4);
                    filePath = Paths.get(downloadPath);
                } catch (Exception e) {
                    System.err.println("Error decrypting file: " + e.getMessage());
                    System.out.println("Saving encrypted file instead");
                }
            }

            //save
            Files.write(filePath, fileData);

            System.out.println("File downloaded successfully to: " + filePath);
        } else {
            System.out.println("Download failed: " + response);
        }
    }

    private void deleteShare() throws IOException {
        System.out.println("\n=== Delete Share ===");

        System.out.print("Enter Share ID to delete: ");
        String shareId = scanner.nextLine().trim();

        sendCommand("DELETE_SHARE");
        out.writeUTF(sessionToken);
        out.writeUTF(shareId);

        String response = in.readUTF();
        System.out.println("Server response: " + response);
    }

    private void searchUsers() throws IOException {
        System.out.println("\n=== Search Users ===");

        System.out.print("Enter search term: ");
        String searchTerm = scanner.nextLine().trim();

        sendCommand("USER_SEARCH");
        out.writeUTF(sessionToken);
        out.writeUTF(searchTerm);

        int count = in.readInt();
        if (count == 0) {
            System.out.println("No users found");
            return;
        }

        System.out.println("Found " + count + " users:");
        for (int i = 0; i < count; i++) {
            String username = in.readUTF();
            System.out.println(" - " + username);
        }
    }

    private void createShareLink() throws IOException {
        System.out.println("\n=== Create Public Share Link ===");

        System.out.print("Enter file path: ");
        String filePath = scanner.nextLine().trim();

        File file = new File(filePath);
        if (!file.exists() || !file.isFile()) {
            System.out.println("File not found or not a regular file");
            return;
        }

        System.out.print("Expiry time in hours: ");
        int expiryHours;
        try {
            expiryHours = Integer.parseInt(scanner.nextLine().trim());
        } catch (NumberFormatException e) {
            System.out.println("Invalid expiry time. Using default (24h)");
            expiryHours = 24;
        }

        System.out.print("Enter encryption password (leave empty for no encryption): ");
        String encryptionPassword = scanner.nextLine().trim();
        boolean encrypt = !encryptionPassword.isEmpty();

        String originalFilename = file.getName();
        byte[] fileData = Files.readAllBytes(file.toPath());

        if (encrypt) {
            try {
                fileData = encryptData(fileData, encryptionPassword);
                originalFilename += ".enc"; // Mark encrypted files
            }
            catch (Exception e) {
                System.err.println("Error encrypting file: " + e.getMessage());
                return;
            }
        }

        sendCommand("CREATE_SHARE_LINK");
        out.writeUTF(sessionToken);
        out.writeUTF(originalFilename);
        out.writeLong(fileData.length);
        out.writeInt(expiryHours);

        //again wait for server
        String readyResponse = in.readUTF();
        if (readyResponse.equals("READY_TO_RECEIVE")) {

            out.write(fileData);
            out.flush();

            String response = in.readUTF();
            if (response.startsWith("SUCCESS")) {
                String shareLink = in.readUTF();
                System.out.println("Public share link created: " + shareLink);

                //extract share ID from link
                String shareId = shareLink.replace("sft://", "");

                if (encrypt) {
                    saveEncryptionInfo(shareId, encryptionPassword);
                }
            }
            else {
                System.out.println("Failed to create share link: " + response);
            }
        }
        else {
            System.out.println("Server not ready to receive: " + readyResponse);
        }
    }

    private void accessShareById() throws IOException {
        System.out.println("\n=== Access Share by ID ===");

        System.out.print("Enter Share ID or link: ");
        String shareInput = scanner.nextLine().trim();

        //extract ID from link if needed
        String shareId = shareInput;
        if (shareInput.startsWith("sft://")) {
            shareId = shareInput.replace("sft://", "");
        }

        sendCommand("ACCESS_SHARE");
        out.writeUTF(sessionToken);
        out.writeUTF(shareId);

        String response = in.readUTF();
        if (response.equals("SUCCESS:SHARE_VALID")) {
            String filename = in.readUTF();
            long fileSize = in.readLong();

            System.out.println("Share information:");
            System.out.println(" - Filename: " + filename);
            System.out.println(" - Size: " + (fileSize / 1024) + " KB");

            System.out.print("Download this file? (y/n): ");
            String download = scanner.nextLine().trim().toLowerCase();

            if (download.startsWith("y")) {
                downloadSharedFile();
            }
        } else {
            System.out.println("Cannot access share: " + response);
        }
    }


    private byte[] encryptData(byte[] data, String password) throws Exception {

        SecretKey key = generateKeyFromPassword(password);
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);

        return cipher.doFinal(data);
    }

    private byte[] decryptData(byte[] encryptedData, String password) throws Exception {

        SecretKey key = generateKeyFromPassword(password);
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);

        return cipher.doFinal(encryptedData);
    }

    private SecretKey generateKeyFromPassword(String password) throws Exception {
        //using PBKDF2 to derive a key from the password
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM);
        KeySpec spec = new PBEKeySpec(password.toCharArray(), SALT, ITERATION_COUNT, KEY_LENGTH);
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, ENCRYPTION_ALGORITHM);
    }

    private void saveEncryptionInfo(String shareId, String password) {
        try {
            //store a hash of the password for future reference
            String passwordHash = hashString(password);
            String encInfo = shareId + ":" + passwordHash;

            Path encryptionFile = Paths.get(CLIENT_FOLDER, "encryption_keys.txt");
            if (!Files.exists(encryptionFile)) {
                Files.createFile(encryptionFile);
            }

            //append
            Files.write(encryptionFile,
                    (encInfo + System.lineSeparator()).getBytes(),
                    java.nio.file.StandardOpenOption.APPEND);

            System.out.println("Encryption information saved for future reference");
        }
        catch (Exception e) {
            System.err.println("Warning: Failed to save encryption information: " + e.getMessage());
        }
    }

    private String hashString(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        }
        catch (NoSuchAlgorithmException e) {
            return Base64.getEncoder().encodeToString(input.getBytes());
        }
    }
}