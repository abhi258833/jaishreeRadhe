package com.security.crypto;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Objects;

/**
 * Defense-in-Depth Cascaded Hybrid Encryption Service.
 * Combines two distinct, orthogonal AEAD cipher suites:
 * - Layer 1 (Inner): AES-256-GCM
 * - Layer 2 (Outer): ChaCha20-Poly1305
 *
 * Demonstrates resilience: if one cipher algorithm or key is mathematically compromised,
 * the remaining layer continues to guarantee confidentiality and authenticity.
 */
public final class CascadedHybridEncryptionService {

    private static final String CHACHA_ALGORITHM = "ChaCha20-Poly1305";
    private static final int CHACHA_KEY_BITS = 256;
    private static final int CHACHA_NONCE_BYTES = 12;

    private final AesGcmEncryptionService aesService;
    private final SecureRandom secureRandom;

    public CascadedHybridEncryptionService() {
        this.aesService = new AesGcmEncryptionService();
        this.secureRandom = new SecureRandom();
    }

    /**
     * Generates a 256-bit ChaCha20 secret key.
     */
    public static SecretKey generateChaChaKey() throws GeneralSecurityException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("ChaCha20");
        keyGenerator.init(CHACHA_KEY_BITS, new SecureRandom());
        return keyGenerator.generateKey();
    }

    /**
     * Encrypts plaintext through two independent AEAD layers:
     * Plaintext -> [AES-256-GCM] -> Intermediate Ciphertext -> [ChaCha20-Poly1305] -> Final Payload.
     */
    public byte[] encryptHybrid(byte[] plaintext, SecretKey aesKey, SecretKey chaChaKey) throws GeneralSecurityException {
        Objects.requireNonNull(plaintext, "Plaintext must not be null");

        // Layer 1: AES-256-GCM
        byte[] aesCiphertext = aesService.encrypt(plaintext, aesKey);

        // Layer 2: ChaCha20-Poly1305
        byte[] chaChaNonce = new byte[CHACHA_NONCE_BYTES];
        secureRandom.nextBytes(chaChaNonce);

        Cipher chaChaCipher = Cipher.getInstance(CHACHA_ALGORITHM);
        chaChaCipher.init(Cipher.ENCRYPT_MODE, chaChaKey, new IvParameterSpec(chaChaNonce));
        byte[] outerCiphertext = chaChaCipher.doFinal(aesCiphertext);

        // Pack: [12-byte ChaCha Nonce][Outer Ciphertext with Poly1305 tag]
        ByteBuffer buffer = ByteBuffer.allocate(chaChaNonce.length + outerCiphertext.length);
        buffer.put(chaChaNonce);
        buffer.put(outerCiphertext);
        return buffer.array();
    }

    /**
     * Decrypts the cascaded payload in reverse order:
     * Final Payload -> [ChaCha20-Poly1305] -> Intermediate Ciphertext -> [AES-256-GCM] -> Plaintext.
     */
    public byte[] decryptHybrid(byte[] hybridPayload, SecretKey aesKey, SecretKey chaChaKey) throws GeneralSecurityException {
        Objects.requireNonNull(hybridPayload, "Payload must not be null");
        if (hybridPayload.length < CHACHA_NONCE_BYTES + 16) {
            throw new IllegalArgumentException("Payload too short for ChaCha20-Poly1305");
        }

        ByteBuffer buffer = ByteBuffer.wrap(hybridPayload);
        byte[] chaChaNonce = new byte[CHACHA_NONCE_BYTES];
        buffer.get(chaChaNonce);

        byte[] outerCiphertext = new byte[buffer.remaining()];
        buffer.get(outerCiphertext);

        // Decrypt Outer Layer: ChaCha20-Poly1305
        Cipher chaChaCipher = Cipher.getInstance(CHACHA_ALGORITHM);
        chaChaCipher.init(Cipher.DECRYPT_MODE, chaChaKey, new IvParameterSpec(chaChaNonce));
        byte[] aesCiphertext = chaChaCipher.doFinal(outerCiphertext);

        // Decrypt Inner Layer: AES-256-GCM
        return aesService.decrypt(aesCiphertext, aesKey);
    }
}
