package com.security.crypto;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class AesGcmEncryptionServiceTest {

    private AesGcmEncryptionService service;
    private SecretKey key;

    @BeforeEach
    void setUp() throws Exception {
        service = new AesGcmEncryptionService();
        key = AesGcmEncryptionService.generateKey();
    }

    @Test
    @DisplayName("Should successfully encrypt and decrypt a string with UTF-8 characters")
    void testEncryptDecryptString() throws GeneralSecurityException {
        String originalMessage = "Top Secret Cryptographic Assessment Payload: \uD83D\uDD10 जय श्री राधे €$¥ §123";

        String base64Encrypted = service.encrypt(originalMessage, key);
        assertNotNull(base64Encrypted);
        assertNotEquals(originalMessage, base64Encrypted);

        String decryptedMessage = service.decrypt(base64Encrypted, key);
        assertEquals(originalMessage, decryptedMessage);
    }

    @Test
    @DisplayName("Should successfully encrypt and decrypt raw byte arrays")
    void testEncryptDecryptBytes() throws GeneralSecurityException {
        byte[] originalBytes = "ArbitraryBinaryData\0\1\2\3\u00FF".getBytes(StandardCharsets.UTF_8);

        byte[] encryptedPayload = service.encrypt(originalBytes, key);
        assertNotNull(encryptedPayload);
        // Payload must be: 12 bytes IV + original bytes length + 16 bytes tag
        assertEquals(EncryptedPayload.IV_LENGTH_BYTES + originalBytes.length + EncryptedPayload.TAG_LENGTH_BYTES, encryptedPayload.length);

        byte[] decryptedBytes = service.decrypt(encryptedPayload, key);
        assertArrayEquals(originalBytes, decryptedBytes);
    }

    @Test
    @DisplayName("Should generate unique nonces for identical plaintexts (Semantic Security / IND-CPA)")
    void testNonceUniqueness() throws GeneralSecurityException {
        String message = "Constant Plaintext Value";

        String cipher1 = service.encrypt(message, key);
        String cipher2 = service.encrypt(message, key);

        assertNotEquals(cipher1, cipher2, "Encrypting identical messages twice must produce different ciphertexts");

        EncryptedPayload p1 = EncryptedPayload.fromBase64(cipher1);
        EncryptedPayload p2 = EncryptedPayload.fromBase64(cipher2);

        assertFalse(Arrays.equals(p1.iv(), p2.iv()), "Each encryption must use a unique 12-byte nonce");
    }

    @Test
    @DisplayName("Should reject decryption when ciphertext or tag is modified")
    void testModifiedCiphertextRejection() throws GeneralSecurityException {
        byte[] plaintext = "Sensitive Financial Transaction: $1,000,000".getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = service.encrypt(plaintext, key);

        // Tamper with the last byte (part of the authentication tag)
        encrypted[encrypted.length - 1] ^= 0x01;

        assertThrows(AEADBadTagException.class, () -> service.decrypt(encrypted, key),
                "Tampered ciphertext/tag must fail AEAD authentication and throw AEADBadTagException");
    }

    @Test
    @DisplayName("Should reject decryption when the IV is modified")
    void testModifiedIVRejection() throws GeneralSecurityException {
        byte[] plaintext = "Confidential Command: TRANSFER".getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = service.encrypt(plaintext, key);

        // Tamper with the first byte of the IV
        encrypted[0] ^= 0x01;

        assertThrows(AEADBadTagException.class, () -> service.decrypt(encrypted, key),
                "Tampered IV must cause AEAD authentication to fail");
    }

    @Test
    @DisplayName("Should reject decryption with an incorrect 256-bit key")
    void testIncorrectKeyRejection() throws Exception {
        byte[] plaintext = "Secret Message".getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = service.encrypt(plaintext, key);

        SecretKey wrongKey = AesGcmEncryptionService.generateKey();

        assertThrows(AEADBadTagException.class, () -> service.decrypt(encrypted, wrongKey),
                "Decryption using a different key must fail authentication");
    }

    @Test
    @DisplayName("Should reject keys that are not 256-bit AES")
    void testRejectNon256BitKey() throws Exception {
        KeyGenerator kg128 = KeyGenerator.getInstance("AES");
        kg128.init(128);
        SecretKey key128 = kg128.generateKey();

        byte[] plaintext = "Test".getBytes(StandardCharsets.UTF_8);
        assertThrows(IllegalArgumentException.class, () -> service.encrypt(plaintext, key128));
    }

    @Test
    @DisplayName("Should reject truncated payload shorter than IV + Tag minimum size")
    void testTruncatedPayloadRejection() {
        byte[] truncated = new byte[EncryptedPayload.MIN_PAYLOAD_BYTES - 1];
        assertThrows(IllegalArgumentException.class, () -> service.decrypt(truncated, key));
    }

    @Test
    @DisplayName("Should support and authenticate Associated Authenticated Data (AAD)")
    void testAssociatedAuthenticatedData() throws GeneralSecurityException {
        byte[] plaintext = "Payload Data".getBytes(StandardCharsets.UTF_8);
        byte[] aad = "header-metadata-user-id:42".getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = service.encrypt(plaintext, key, aad);

        // Successfully decrypt with matching AAD
        byte[] decrypted = service.decrypt(encrypted, key, aad);
        assertArrayEquals(plaintext, decrypted);

        // Fails if AAD is tampered
        byte[] tamperedAad = "header-metadata-user-id:43".getBytes(StandardCharsets.UTF_8);
        assertThrows(AEADBadTagException.class, () -> service.decrypt(encrypted, key, tamperedAad));

        // Fails if AAD is omitted
        assertThrows(AEADBadTagException.class, () -> service.decrypt(encrypted, key, null));
    }
}
