package com.security.crypto;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Objects;

/**
 * Enterprise-grade AES-256-GCM encryption and decryption service.
 * <p>
 * Key characteristics:
 * - Cipher Algorithm: AES/GCM/NoPadding (Authenticated Encryption with Associated Data - AEAD)
 * - Key Length: 256 bits
 * - Nonce (IV) Length: 96 bits (12 bytes), cryptographically random per encryption
 * - Authentication Tag Length: 128 bits (16 bytes)
 * - String Encoding: UTF-8
 */
public final class AesGcmEncryptionService {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    public static final int KEY_SIZE_BITS = 256;
    public static final int KEY_SIZE_BYTES = KEY_SIZE_BITS / 8; // 32 bytes
    public static final int IV_SIZE_BYTES = 12; // 96 bits recommended by NIST SP 800-38D
    public static final int TAG_SIZE_BITS = 128; // 16 bytes maximum security tag

    private final SecureRandom secureRandom;

    /**
     * Initializes service with default CSPRNG (Cryptographically Secure Pseudo-Random Number Generator).
     */
    public AesGcmEncryptionService() {
        this(new SecureRandom());
    }

    /**
     * Initializes service with a specific SecureRandom instance (useful for testing or specific providers).
     */
    public AesGcmEncryptionService(SecureRandom secureRandom) {
        this.secureRandom = Objects.requireNonNull(secureRandom, "SecureRandom must not be null");
    }

    /**
     * Generates a cryptographically strong 256-bit AES symmetric key.
     *
     * @return 256-bit SecretKey.
     * @throws NoSuchAlgorithmException if the AES algorithm is unavailable in the JRE.
     */
    public static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        // KeyGenerator should be initialized with 256 bits and a secure random source
        keyGenerator.init(KEY_SIZE_BITS, new SecureRandom());
        return keyGenerator.generateKey();
    }

    // =========================================================================
    // High-Level String APIs
    // =========================================================================

    /**
     * Encrypts a UTF-8 String into a Base64-encoded combined payload [IV + Ciphertext + Tag].
     *
     * @param plaintext Plaintext string to encrypt.
     * @param key       256-bit AES secret key.
     * @return Base64-encoded string representing the combined encrypted payload.
     * @throws GeneralSecurityException if encryption fails.
     */
    public String encrypt(String plaintext, SecretKey key) throws GeneralSecurityException {
        Objects.requireNonNull(plaintext, "Plaintext must not be null");
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = encrypt(plaintextBytes, key);
        return EncryptedPayload.fromCombinedBytes(encrypted).toBase64();
    }

    /**
     * Decrypts a Base64-encoded combined payload [IV + Ciphertext + Tag] into a UTF-8 String.
     *
     * @param base64Payload Base64-encoded combined payload string.
     * @param key           256-bit AES secret key.
     * @return Decrypted plaintext string.
     * @throws AEADBadTagException      if the ciphertext was modified or the key is incorrect.
     * @throws GeneralSecurityException if decryption fails.
     */
    public String decrypt(String base64Payload, SecretKey key) throws GeneralSecurityException {
        Objects.requireNonNull(base64Payload, "Base64 payload must not be null");
        EncryptedPayload payload = EncryptedPayload.fromBase64(base64Payload);
        byte[] decryptedBytes = decrypt(payload.toCombinedBytes(), key);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    // =========================================================================
    // Byte-Array Combined Payload APIs [12-byte IV][Ciphertext + 16-byte Tag]
    // =========================================================================

    /**
     * Encrypts plaintext bytes and returns a combined binary payload: [IV (12 bytes)][Ciphertext + Tag (16 bytes)].
     *
     * @param plaintext Raw bytes to encrypt.
     * @param key       256-bit AES secret key.
     * @return Combined byte array containing IV and ciphertext with authentication tag.
     * @throws GeneralSecurityException if encryption fails.
     */
    public byte[] encrypt(byte[] plaintext, SecretKey key) throws GeneralSecurityException {
        return encrypt(plaintext, key, null);
    }

    /**
     * Decrypts a combined binary payload [IV (12 bytes)][Ciphertext + Tag (16 bytes)].
     *
     * @param combinedPayload Combined payload containing IV and ciphertext with tag.
     * @param key             256-bit AES secret key.
     * @return Original decrypted plaintext bytes.
     * @throws AEADBadTagException      if authentication fails (tampering or wrong key).
     * @throws GeneralSecurityException if decryption parameters are invalid.
     */
    public byte[] decrypt(byte[] combinedPayload, SecretKey key) throws GeneralSecurityException {
        return decrypt(combinedPayload, key, null);
    }

    // =========================================================================
    // Authenticated Encryption with Associated Data (AEAD) APIs
    // =========================================================================

    /**
     * Encrypts raw plaintext with optional Associated Authenticated Data (AAD).
     *
     * @param plaintext      Raw bytes to encrypt.
     * @param key            256-bit AES secret key.
     * @param associatedData Optional unencrypted data authenticated by the tag (e.g., headers/metadata).
     * @return Combined byte array containing [IV (12 bytes)][Ciphertext + Tag (16 bytes)].
     * @throws GeneralSecurityException if encryption fails.
     */
    public byte[] encrypt(byte[] plaintext, SecretKey key, byte[] associatedData) throws GeneralSecurityException {
        Objects.requireNonNull(plaintext, "Plaintext must not be null");
        validateKey(key);

        // Generate fresh, cryptographically secure 12-byte nonce (IV)
        byte[] iv = new byte[IV_SIZE_BYTES];
        secureRandom.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_SIZE_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

        if (associatedData != null && associatedData.length > 0) {
            cipher.updateAAD(associatedData);
        }

        // Under AES-GCM, doFinal produces ciphertext concatenated with the 128-bit authentication tag
        byte[] ciphertextWithTag = cipher.doFinal(plaintext);

        EncryptedPayload payload = new EncryptedPayload(iv, ciphertextWithTag);
        return payload.toCombinedBytes();
    }

    /**
     * Decrypts combined binary payload with optional Associated Authenticated Data (AAD).
     *
     * @param combinedPayload Combined byte array containing [IV (12 bytes)][Ciphertext + Tag (16 bytes)].
     * @param key             256-bit AES secret key.
     * @param associatedData  Optional unencrypted data that was authenticated during encryption.
     * @return Original decrypted plaintext bytes.
     * @throws AEADBadTagException      if authentication fails (tampering or wrong key).
     * @throws GeneralSecurityException if decryption fails.
     */
    public byte[] decrypt(byte[] combinedPayload, SecretKey key, byte[] associatedData) throws GeneralSecurityException {
        Objects.requireNonNull(combinedPayload, "Combined payload must not be null");
        validateKey(key);

        EncryptedPayload payload = EncryptedPayload.fromCombinedBytes(combinedPayload);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_SIZE_BITS, payload.iv());
        cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);

        if (associatedData != null && associatedData.length > 0) {
            cipher.updateAAD(associatedData);
        }

        // Verifies the authentication tag automatically. Throws AEADBadTagException if tampered or wrong key.
        return cipher.doFinal(payload.ciphertextWithTag());
    }

    /**
     * Validates that the provided SecretKey satisfies AES-256 requirements.
     */
    private void validateKey(SecretKey key) {
        Objects.requireNonNull(key, "SecretKey must not be null");
        if (!ALGORITHM.equalsIgnoreCase(key.getAlgorithm())) {
            throw new IllegalArgumentException("Invalid key algorithm: expected " + ALGORITHM + " but got " + key.getAlgorithm());
        }
        byte[] encoded = key.getEncoded();
        if (encoded != null && encoded.length != KEY_SIZE_BYTES) {
            throw new IllegalArgumentException("Invalid key size: expected " + KEY_SIZE_BYTES + " bytes (" + KEY_SIZE_BITS + " bits), but got " + encoded.length + " bytes.");
        }
    }
}
