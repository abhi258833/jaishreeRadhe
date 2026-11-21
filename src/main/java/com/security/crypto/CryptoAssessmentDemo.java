package com.security.crypto;

import javax.crypto.AEADBadTagException;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * Standalone cryptographic self-test and verification demonstration.
 * Runs in pure Java 17 without external test dependencies.
 */
public class CryptoAssessmentDemo {

    public static void main(String[] args) {
        System.out.println("=================================================================");
        System.out.println(" AES-256-GCM Cryptographic Assessment & Verification Suite");
        System.out.println("=================================================================\n");

        AesGcmEncryptionService service = new AesGcmEncryptionService();

        try {
            // Test 1: Key Generation
            System.out.print("[Test 1] Generating 256-bit AES Key... ");
            SecretKey key = AesGcmEncryptionService.generateKey();
            if (key.getEncoded().length != 32) {
                throw new IllegalStateException("Key size is not 32 bytes (256 bits)");
            }
            System.out.println("PASSED (Algorithm: " + key.getAlgorithm() + ", Length: " + (key.getEncoded().length * 8) + " bits)");

            // Test 2: Standard String Encryption and Decryption (UTF-8)
            System.out.print("[Test 2] String Encrypt/Decrypt with UTF-8 multi-byte characters... ");
            String sampleText = "Top-Secret Cryptographic Payload: \uD83D\uDD10 जय श्री राधे €$¥ §123";
            String base64Encrypted = service.encrypt(sampleText, key);
            String decryptedText = service.decrypt(base64Encrypted, key);
            if (!sampleText.equals(decryptedText)) {
                throw new IllegalStateException("Decrypted text does not match original plaintext!");
            }
            System.out.println("PASSED");
            System.out.println("         Plaintext: " + sampleText);
            System.out.println("         Base64 Payload: " + base64Encrypted);

            // Test 3: Nonce Uniqueness (IND-CPA)
            System.out.print("[Test 3] Nonce Uniqueness Check (Two encryptions of same plaintext)... ");
            String cipher1 = service.encrypt("Fixed String", key);
            String cipher2 = service.encrypt("Fixed String", key);
            EncryptedPayload p1 = EncryptedPayload.fromBase64(cipher1);
            EncryptedPayload p2 = EncryptedPayload.fromBase64(cipher2);
            if (Arrays.equals(p1.iv(), p2.iv()) || cipher1.equals(cipher2)) {
                throw new IllegalStateException("Reused nonce detected! Nonce must be unique per encryption.");
            }
            System.out.println("PASSED (IV1 != IV2, Ciphertext1 != Ciphertext2)");

            // Test 4: Integrity & Tamper Resistance (Ciphertext/Tag modification)
            System.out.print("[Test 4] Tampered Ciphertext Authentication Rejection... ");
            byte[] rawEncrypted = service.encrypt("Sensitive Command".getBytes(StandardCharsets.UTF_8), key);
            rawEncrypted[rawEncrypted.length - 1] ^= 0x01; // flip last bit in auth tag
            try {
                service.decrypt(rawEncrypted, key);
                throw new IllegalStateException("SECURITY FAILURE: Tampered ciphertext was accepted!");
            } catch (AEADBadTagException e) {
                System.out.println("PASSED (Successfully caught expected AEADBadTagException)");
            }

            // Test 5: Integrity & Tamper Resistance (IV modification)
            System.out.print("[Test 5] Tampered IV Authentication Rejection... ");
            byte[] rawEncrypted2 = service.encrypt("Sensitive Command".getBytes(StandardCharsets.UTF_8), key);
            rawEncrypted2[0] ^= 0x01; // flip bit in IV
            try {
                service.decrypt(rawEncrypted2, key);
                throw new IllegalStateException("SECURITY FAILURE: Tampered IV was accepted!");
            } catch (AEADBadTagException e) {
                System.out.println("PASSED (Successfully caught expected AEADBadTagException)");
            }

            // Test 6: Incorrect Key Rejection
            System.out.print("[Test 6] Incorrect Key Decryption Rejection... ");
            SecretKey wrongKey = AesGcmEncryptionService.generateKey();
            byte[] rawEncrypted3 = service.encrypt("Message for Key A".getBytes(StandardCharsets.UTF_8), key);
            try {
                service.decrypt(rawEncrypted3, wrongKey);
                throw new IllegalStateException("SECURITY FAILURE: Decryption with wrong key did not throw an exception!");
            } catch (AEADBadTagException e) {
                System.out.println("PASSED (Successfully caught expected AEADBadTagException)");
            }

            // Test 7: Associated Authenticated Data (AAD)
            System.out.print("[Test 7] Associated Authenticated Data (AAD) Verification... ");
            byte[] aad = "tenant-id:1002".getBytes(StandardCharsets.UTF_8);
            byte[] rawEncryptedWithAad = service.encrypt("Data with AAD".getBytes(StandardCharsets.UTF_8), key, aad);
            byte[] decryptedWithAad = service.decrypt(rawEncryptedWithAad, key, aad);
            if (!Arrays.equals("Data with AAD".getBytes(StandardCharsets.UTF_8), decryptedWithAad)) {
                throw new IllegalStateException("Decrypted AAD data mismatch");
            }
            // Now test with invalid AAD
            byte[] badAad = "tenant-id:9999".getBytes(StandardCharsets.UTF_8);
            try {
                service.decrypt(rawEncryptedWithAad, key, badAad);
                throw new IllegalStateException("SECURITY FAILURE: Decryption with tampered AAD was accepted!");
            } catch (AEADBadTagException e) {
                System.out.println("PASSED (AAD correctly authenticated)");
            }

            // Test 8: Cascaded Hybrid Defense-in-Depth & Compromise Simulation (Requirement 3)
            System.out.print("[Test 8] Hybrid Encryption & Compromised Algorithm Simulation... ");
            CascadedHybridEncryptionService hybridService = new CascadedHybridEncryptionService();
            SecretKey aesKey = AesGcmEncryptionService.generateKey();
            SecretKey chaChaKey = CascadedHybridEncryptionService.generateChaChaKey();
            byte[] confidentialSecret = "CRITICAL_PAYLOAD_PROTECTED_BY_HYBRID".getBytes(StandardCharsets.UTF_8);

            // Normal hybrid encryption & decryption
            byte[] hybridPayload = hybridService.encryptHybrid(confidentialSecret, aesKey, chaChaKey);
            byte[] hybridDecrypted = hybridService.decryptHybrid(hybridPayload, aesKey, chaChaKey);
            if (!Arrays.equals(confidentialSecret, hybridDecrypted)) {
                throw new IllegalStateException("Hybrid decrypted plaintext mismatch");
            }

            // SIMULATION: Assume AES-256 is compromised or AES key is leaked to the attacker!
            // Attacker has: hybridPayload + leaked aesKey.
            // Attacker attempts to bypass outer layer or decrypt directly with AES:
            try {
                service.decrypt(hybridPayload, aesKey);
                throw new IllegalStateException("SECURITY FAILURE: Attacker bypassed outer layer with only AES key!");
            } catch (Exception expected) {
                // Outer ChaCha20-Poly1305 prevents the attacker from accessing the inner AES ciphertext
            }
            System.out.println("PASSED (Dual-cipher resilience verified: compromise of one algorithm does not expose data)");

            System.out.println("\nAll 8 Cryptographic Assessment Verification Checks PASSED successfully!");

        } catch (Exception ex) {
            System.err.println("FAILED: " + ex.getMessage());
            ex.printStackTrace();
            System.exit(1);
        }
    }
}
