package com.security.crypto;

import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Objects;

/**
 * Manages secure local storage and retrieval of AES-256 keys using PKCS#12 KeyStores.
 *
 * PKCS#12 (.p12) is the default KeyStore type since Java 9 (JEP 229).
 * It encrypts stored secret keys using Password-Based Encryption (PBKDF2 + AES key wrapping).
 *
 * Key Lifecycle:
 *   1. generateKey()     → creates a fresh 256-bit AES key in memory
 *   2. storeKey()        → persists it to a password-protected .p12 file on disk
 *   3. loadKey()         → retrieves it from the .p12 file at application startup
 *   4. deleteKey()       → removes a key alias from the keystore (rotation)
 *   5. keyExists()       → checks whether a key alias is present
 */
public final class AesKeyStoreManager {

    private static final String KEYSTORE_TYPE = "PKCS12";

    private AesKeyStoreManager() {
        // Utility class — no instantiation
    }

    /**
     * Stores an AES SecretKey into a password-protected PKCS#12 KeyStore file.
     *
     * @param key              The 256-bit AES SecretKey to persist.
     * @param alias            Unique identifier for the key (e.g., "data-encryption-key-v1").
     * @param keyStorePassword Password protecting the keystore file itself.
     * @param keyPassword      Password protecting the individual key entry.
     * @param keyStorePath     File system path where the .p12 file will be created or updated.
     */
    public static void storeKey(SecretKey key, String alias, char[] keyStorePassword,
                                char[] keyPassword, Path keyStorePath)
            throws GeneralSecurityException, IOException {

        Objects.requireNonNull(key, "SecretKey must not be null");
        Objects.requireNonNull(alias, "Key alias must not be null");

        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);

        // Load existing KeyStore if it exists, otherwise create a new empty one
        if (keyStorePath.toFile().exists()) {
            try (FileInputStream fis = new FileInputStream(keyStorePath.toFile())) {
                keyStore.load(fis, keyStorePassword);
            }
        } else {
            keyStore.load(null, keyStorePassword); // Initialize empty keystore
        }

        // Wrap the key inside a password-protected entry
        KeyStore.SecretKeyEntry keyEntry = new KeyStore.SecretKeyEntry(key);
        KeyStore.ProtectionParameter protection = new KeyStore.PasswordProtection(keyPassword);
        keyStore.setEntry(alias, keyEntry, protection);

        // Write the updated keystore to disk
        try (FileOutputStream fos = new FileOutputStream(keyStorePath.toFile())) {
            keyStore.store(fos, keyStorePassword);
        }
    }

    /**
     * Loads an AES SecretKey from a PKCS#12 KeyStore file.
     *
     * @param alias            The key alias to retrieve.
     * @param keyStorePassword Password protecting the keystore file.
     * @param keyPassword      Password protecting the key entry.
     * @param keyStorePath     File system path of the .p12 file.
     * @return The 256-bit AES SecretKey.
     */
    public static SecretKey loadKey(String alias, char[] keyStorePassword,
                                    char[] keyPassword, Path keyStorePath)
            throws GeneralSecurityException, IOException {

        Objects.requireNonNull(alias, "Key alias must not be null");

        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
        try (FileInputStream fis = new FileInputStream(keyStorePath.toFile())) {
            keyStore.load(fis, keyStorePassword);
        }

        KeyStore.ProtectionParameter protection = new KeyStore.PasswordProtection(keyPassword);
        KeyStore.Entry entry = keyStore.getEntry(alias, protection);

        if (!(entry instanceof KeyStore.SecretKeyEntry secretKeyEntry)) {
            throw new IllegalArgumentException(
                    "No SecretKey entry found for alias: '" + alias + "'. "
                    + "Available aliases: " + java.util.Collections.list(keyStore.aliases()));
        }

        return secretKeyEntry.getSecretKey();
    }

    /**
     * Checks whether a key alias exists in the KeyStore.
     */
    public static boolean keyExists(String alias, char[] keyStorePassword, Path keyStorePath)
            throws GeneralSecurityException, IOException {

        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
        try (FileInputStream fis = new FileInputStream(keyStorePath.toFile())) {
            keyStore.load(fis, keyStorePassword);
        }
        return keyStore.containsAlias(alias);
    }

    /**
     * Deletes a key alias from the KeyStore (used during key rotation).
     */
    public static void deleteKey(String alias, char[] keyStorePassword, Path keyStorePath)
            throws GeneralSecurityException, IOException {

        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
        try (FileInputStream fis = new FileInputStream(keyStorePath.toFile())) {
            keyStore.load(fis, keyStorePassword);
        }

        if (!keyStore.containsAlias(alias)) {
            throw new IllegalArgumentException("Alias '" + alias + "' not found in keystore.");
        }

        keyStore.deleteEntry(alias);

        try (FileOutputStream fos = new FileOutputStream(keyStorePath.toFile())) {
            keyStore.store(fos, keyStorePassword);
        }
    }
}
