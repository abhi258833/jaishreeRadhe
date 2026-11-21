package com.security.crypto;

import javax.crypto.AEADBadTagException;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * Day 3: Key Lifecycle & Storage Architecture — Interactive Demo.
 *
 * Demonstrates:
 *   1. PKCS#12 KeyStore — Save/Load/Delete keys to encrypted .p12 files
 *   2. Envelope Encryption — KEK/DEK pattern used by AWS KMS, GCP Cloud KMS
 *   3. Key Rotation — Rotate KEK without re-encrypting data
 *   4. Memory Zeroization — Scrub sensitive key material from heap
 */
public class Day3KeyLifecycleDemo {

    public static void main(String[] args) {
        System.out.println("=================================================================");
        System.out.println(" Day 3: Key Lifecycle & Storage Architecture Demo");
        System.out.println("=================================================================\n");

        try {
            testKeyStoreLifecycle();
            testEnvelopeEncryption();
            testKekRotation();
            testMemoryZeroization();

            System.out.println("\n=================================================================");
            System.out.println(" All Day 3 Key Lifecycle Tests PASSED!");
            System.out.println("=================================================================");

        } catch (Exception ex) {
            System.err.println("FAILED: " + ex.getMessage());
            ex.printStackTrace();
            System.exit(1);
        }
    }

    // =========================================================================
    // Test 1: PKCS#12 KeyStore Lifecycle
    // =========================================================================
    private static void testKeyStoreLifecycle() throws Exception {
        System.out.println("--- Section 1: PKCS#12 KeyStore Lifecycle ---\n");

        Path tempKeyStore = Files.createTempFile("crypto-demo-", ".p12");
        Files.delete(tempKeyStore); // We want storeKey to create it fresh

        char[] storePass = "KeyStore-Master-Password-2024!".toCharArray();
        char[] keyPass   = "Individual-Key-Password-2024!".toCharArray();
        String alias     = "aes256-gcm-master-key-v1";

        // 1a. Generate and store a key
        System.out.print("[1a] Generate & store key to PKCS#12 file... ");
        SecretKey originalKey = AesGcmEncryptionService.generateKey();
        AesKeyStoreManager.storeKey(originalKey, alias, storePass, keyPass, tempKeyStore);
        System.out.println("PASSED");
        System.out.println("     KeyStore path: " + tempKeyStore);
        System.out.println("     Key alias: " + alias);
        System.out.println("     Key algorithm: " + originalKey.getAlgorithm()
                + ", size: " + (originalKey.getEncoded().length * 8) + " bits");

        // 1b. Load the key back and verify it matches
        System.out.print("[1b] Load key from PKCS#12 and verify byte equality... ");
        SecretKey loadedKey = AesKeyStoreManager.loadKey(alias, storePass, keyPass, tempKeyStore);
        if (!Arrays.equals(originalKey.getEncoded(), loadedKey.getEncoded())) {
            throw new IllegalStateException("Loaded key does not match original!");
        }
        System.out.println("PASSED (Loaded key matches original)");

        // 1c. Encrypt with original, decrypt with loaded (cross-verification)
        System.out.print("[1c] Encrypt with original key, decrypt with loaded key... ");
        AesGcmEncryptionService service = new AesGcmEncryptionService();
        String secret = "This was encrypted before the key was persisted";
        String encrypted = service.encrypt(secret, originalKey);
        String decrypted = service.decrypt(encrypted, loadedKey);
        if (!secret.equals(decrypted)) {
            throw new IllegalStateException("Cross-key decrypt failed!");
        }
        System.out.println("PASSED");

        // 1d. Check key existence
        System.out.print("[1d] Verify key existence check... ");
        boolean exists = AesKeyStoreManager.keyExists(alias, storePass, tempKeyStore);
        boolean ghost  = AesKeyStoreManager.keyExists("non-existent-key", storePass, tempKeyStore);
        if (!exists || ghost) {
            throw new IllegalStateException("Key existence check failed!");
        }
        System.out.println("PASSED ('" + alias + "' exists: " + exists + ", 'non-existent': " + ghost + ")");

        // 1e. Delete key (key rotation cleanup)
        System.out.print("[1e] Delete key from keystore (rotation cleanup)... ");
        AesKeyStoreManager.deleteKey(alias, storePass, tempKeyStore);
        boolean afterDelete = AesKeyStoreManager.keyExists(alias, storePass, tempKeyStore);
        if (afterDelete) {
            throw new IllegalStateException("Key still exists after deletion!");
        }
        System.out.println("PASSED (Key deleted successfully)");

        // Cleanup temp file
        Files.deleteIfExists(tempKeyStore);
        System.out.println();
    }

    // =========================================================================
    // Test 2: Envelope Encryption (KEK / DEK Pattern)
    // =========================================================================
    private static void testEnvelopeEncryption() throws Exception {
        System.out.println("--- Section 2: Envelope Encryption (KEK / DEK Pattern) ---\n");

        EnvelopeEncryptionService envelopeService = new EnvelopeEncryptionService();

        // The KEK (Key Encryption Key) — in production, this lives in AWS KMS / HSM
        SecretKey kek = AesGcmEncryptionService.generateKey();

        byte[] sensitiveRecord = "Patient SSN: 123-45-6789 | Diagnosis: Confidential"
                .getBytes(StandardCharsets.UTF_8);

        // 2a. Seal (encrypt) using envelope encryption
        System.out.print("[2a] Seal data with envelope encryption... ");
        EnvelopeEncryptionService.Envelope envelope = envelopeService.seal(sensitiveRecord, kek);
        System.out.println("PASSED");
        System.out.println("     Encrypted DEK size: " + envelope.encryptedDek().length + " bytes");
        System.out.println("     Data ciphertext size: " + envelope.dataCiphertext().length + " bytes");
        System.out.println("     Envelope Base64: " + envelope.toBase64().substring(0, 60) + "...");

        // 2b. Unseal (decrypt) the envelope
        System.out.print("[2b] Unseal envelope to recover plaintext... ");
        byte[] recovered = envelopeService.unseal(envelope, kek);
        if (!Arrays.equals(sensitiveRecord, recovered)) {
            throw new IllegalStateException("Envelope decryption produced wrong plaintext!");
        }
        System.out.println("PASSED");
        System.out.println("     Recovered: " + new String(recovered, StandardCharsets.UTF_8));

        // 2c. Wrong KEK cannot unseal
        System.out.print("[2c] Wrong KEK cannot unseal envelope... ");
        SecretKey wrongKek = AesGcmEncryptionService.generateKey();
        try {
            envelopeService.unseal(envelope, wrongKek);
            throw new IllegalStateException("SECURITY FAILURE: Wrong KEK unsealed the envelope!");
        } catch (AEADBadTagException e) {
            System.out.println("PASSED (AEADBadTagException thrown as expected)");
        }

        // 2d. Demonstrate per-record DEK isolation
        System.out.print("[2d] Per-record DEK isolation (two records, different DEKs)... ");
        byte[] record1 = "Record 1: Alice".getBytes(StandardCharsets.UTF_8);
        byte[] record2 = "Record 2: Bob".getBytes(StandardCharsets.UTF_8);
        EnvelopeEncryptionService.Envelope env1 = envelopeService.seal(record1, kek);
        EnvelopeEncryptionService.Envelope env2 = envelopeService.seal(record2, kek);
        // The encrypted DEKs must be different (different random DEK per record)
        if (Arrays.equals(env1.encryptedDek(), env2.encryptedDek())) {
            throw new IllegalStateException("Two records share the same DEK!");
        }
        System.out.println("PASSED (Each record has a unique DEK)");
        System.out.println();
    }

    // =========================================================================
    // Test 3: KEK Rotation Without Re-encrypting Data
    // =========================================================================
    private static void testKekRotation() throws Exception {
        System.out.println("--- Section 3: KEK Rotation (Zero Data Re-encryption) ---\n");

        EnvelopeEncryptionService envelopeService = new EnvelopeEncryptionService();

        SecretKey oldKek = AesGcmEncryptionService.generateKey();
        SecretKey newKek = AesGcmEncryptionService.generateKey();

        byte[] data = "Critical financial record: $1,000,000 wire transfer"
                .getBytes(StandardCharsets.UTF_8);

        // Seal with old KEK
        EnvelopeEncryptionService.Envelope originalEnvelope = envelopeService.seal(data, oldKek);

        // 3a. Rotate KEK
        System.out.print("[3a] Rotate KEK (re-wrap DEK, data ciphertext unchanged)... ");
        EnvelopeEncryptionService.Envelope rotatedEnvelope =
                envelopeService.rotateKek(originalEnvelope, oldKek, newKek);

        // The data ciphertext must be IDENTICAL (no re-encryption of data!)
        if (!Arrays.equals(originalEnvelope.dataCiphertext(), rotatedEnvelope.dataCiphertext())) {
            throw new IllegalStateException("Data ciphertext changed during KEK rotation!");
        }
        // But the encrypted DEK must be DIFFERENT (re-wrapped under new KEK)
        if (Arrays.equals(originalEnvelope.encryptedDek(), rotatedEnvelope.encryptedDek())) {
            throw new IllegalStateException("Encrypted DEK did not change during rotation!");
        }
        System.out.println("PASSED");
        System.out.println("     Data ciphertext: UNCHANGED (zero re-encryption cost)");
        System.out.println("     Encrypted DEK: CHANGED (re-wrapped under new KEK)");

        // 3b. Old KEK can no longer unseal the rotated envelope
        System.out.print("[3b] Old KEK rejected after rotation... ");
        try {
            envelopeService.unseal(rotatedEnvelope, oldKek);
            throw new IllegalStateException("SECURITY FAILURE: Old KEK still works after rotation!");
        } catch (AEADBadTagException e) {
            System.out.println("PASSED (Old KEK correctly rejected)");
        }

        // 3c. New KEK successfully unseals the rotated envelope
        System.out.print("[3c] New KEK successfully unseals rotated envelope... ");
        byte[] recoveredAfterRotation = envelopeService.unseal(rotatedEnvelope, newKek);
        if (!Arrays.equals(data, recoveredAfterRotation)) {
            throw new IllegalStateException("Data corrupted after KEK rotation!");
        }
        System.out.println("PASSED");
        System.out.println("     Recovered: " + new String(recoveredAfterRotation, StandardCharsets.UTF_8));
        System.out.println();
    }

    // =========================================================================
    // Test 4: Memory Zeroization
    // =========================================================================
    private static void testMemoryZeroization() throws Exception {
        System.out.println("--- Section 4: Memory Zeroization ---\n");

        System.out.print("[4a] Demonstrate byte[] zeroization after key use... ");
        SecretKey tempKey = AesGcmEncryptionService.generateKey();
        byte[] keyMaterial = tempKey.getEncoded();

        // Before: key bytes are present
        boolean allZeroBefore = true;
        for (byte b : keyMaterial) {
            if (b != 0) { allZeroBefore = false; break; }
        }

        // Zeroize
        Arrays.fill(keyMaterial, (byte) 0);

        // After: all bytes must be zero
        boolean allZeroAfter = true;
        for (byte b : keyMaterial) {
            if (b != 0) { allZeroAfter = false; break; }
        }

        if (allZeroBefore || !allZeroAfter) {
            throw new IllegalStateException("Zeroization failed!");
        }
        System.out.println("PASSED");
        System.out.println("     Before zeroization: contained non-zero key material");
        System.out.println("     After zeroization: all 32 bytes are 0x00");

        System.out.print("[4b] Demonstrate char[] password zeroization... ");
        char[] password = "My-Super-Secret-Password!".toCharArray();
        // ... use password for KeyStore operations ...
        Arrays.fill(password, '\0');
        boolean passwordCleared = true;
        for (char c : password) {
            if (c != '\0') { passwordCleared = false; break; }
        }
        if (!passwordCleared) {
            throw new IllegalStateException("Password zeroization failed!");
        }
        System.out.println("PASSED");
        System.out.println("     char[] password scrubbed from memory (unlike immutable String)");
    }
}
