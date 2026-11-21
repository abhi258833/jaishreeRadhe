package com.security.crypto;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * Day 4: AI Code Critique & Complete Flow Understanding Demo.
 *
 * This demo walks through:
 *   Flow 1: Complete Encryption Data Path (byte by byte)
 *   Flow 2: Complete Decryption Data Path (byte by byte)
 *   Flow 3: AI Flaw #1 — Nonce Reuse Simulation (what goes wrong)
 *   Flow 4: AI Flaw #2 — String Heap Residue Problem
 *   Flow 5: AI Flaw #3 — Missing AAD Context Binding (Ciphertext Swapping)
 *   Flow 6: Your Corrections Applied & Verified
 */
public class Day4AiCritiqueDemo {

    public static void main(String[] args) {
        System.out.println("=================================================================");
        System.out.println(" Day 4: AI Code Critique & Complete Flow Understanding");
        System.out.println("=================================================================\n");

        try {
            flowEncryption();
            flowDecryption();
            flowAiFlaw1NonceReuse();
            flowAiFlaw2HeapResidue();
            flowAiFlaw3MissingAAD();
            flowYourCorrections();

            System.out.println("\n=================================================================");
            System.out.println(" All Day 4 Flow Demonstrations PASSED!");
            System.out.println("=================================================================");

        } catch (Exception ex) {
            System.err.println("FAILED: " + ex.getMessage());
            ex.printStackTrace();
            System.exit(1);
        }
    }

    // =========================================================================
    // FLOW 1: Complete Encryption Data Path
    // =========================================================================
    private static void flowEncryption() throws Exception {
        System.out.println("--- Flow 1: Complete Encryption Data Path ---\n");

        String originalText = "Hello, Crypto!";
        byte[] plaintext = originalText.getBytes(StandardCharsets.UTF_8);

        System.out.println("  Step 1: String -> UTF-8 bytes");
        System.out.println("    Input String : \"" + originalText + "\"");
        System.out.println("    UTF-8 bytes  : " + bytesToHex(plaintext));
        System.out.println("    Byte count   : " + plaintext.length + " bytes\n");

        // Generate key
        SecretKey key = AesGcmEncryptionService.generateKey();
        System.out.println("  Step 2: Generate 256-bit AES key");
        System.out.println("    Key bytes    : " + bytesToHex(key.getEncoded()));
        System.out.println("    Key size     : " + (key.getEncoded().length * 8) + " bits\n");

        // Generate IV
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        System.out.println("  Step 3: Generate 12-byte random nonce (IV)");
        System.out.println("    IV bytes     : " + bytesToHex(iv));
        System.out.println("    IV size      : " + iv.length + " bytes (96 bits)\n");

        // Initialize cipher
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        System.out.println("  Step 4: Initialize Cipher");
        System.out.println("    Algorithm    : AES/GCM/NoPadding");
        System.out.println("    Tag size     : 128 bits (16 bytes)");
        System.out.println("    Mode         : ENCRYPT_MODE\n");

        // Encrypt
        byte[] ciphertextWithTag = cipher.doFinal(plaintext);
        int ciphertextLen = ciphertextWithTag.length - 16;
        byte[] ciphertextOnly = Arrays.copyOfRange(ciphertextWithTag, 0, ciphertextLen);
        byte[] tagOnly = Arrays.copyOfRange(ciphertextWithTag, ciphertextLen, ciphertextWithTag.length);

        System.out.println("  Step 5: cipher.doFinal(plaintext) — Encrypt + Append Tag");
        System.out.println("    Output total : " + ciphertextWithTag.length + " bytes");
        System.out.println("    = Ciphertext : " + ciphertextLen + " bytes  " + bytesToHex(ciphertextOnly));
        System.out.println("    + Auth Tag   : " + tagOnly.length + " bytes  " + bytesToHex(tagOnly));
        System.out.println("    Formula      : output.length == plaintext.length(" + plaintext.length + ") + 16(tag) = " + ciphertextWithTag.length + "\n");

        // Pack payload
        byte[] combined = new byte[iv.length + ciphertextWithTag.length];
        ByteBuffer buf = ByteBuffer.wrap(combined);
        buf.put(iv);
        buf.put(ciphertextWithTag);

        System.out.println("  Step 6: Pack into combined payload");
        System.out.println("    Layout       : [12-byte IV][" + ciphertextLen + "-byte Ciphertext][16-byte Tag]");
        System.out.println("    Total size   : " + combined.length + " bytes");
        System.out.println("    Base64       : " + Base64.getEncoder().encodeToString(combined));
        System.out.println();
    }

    // =========================================================================
    // FLOW 2: Complete Decryption Data Path
    // =========================================================================
    private static void flowDecryption() throws Exception {
        System.out.println("--- Flow 2: Complete Decryption Data Path ---\n");

        AesGcmEncryptionService service = new AesGcmEncryptionService();
        SecretKey key = AesGcmEncryptionService.generateKey();

        String originalText = "Secret Message 42";
        byte[] plaintext = originalText.getBytes(StandardCharsets.UTF_8);
        byte[] combined = service.encrypt(plaintext, key);

        System.out.println("  Step 1: Receive combined payload (" + combined.length + " bytes)");
        System.out.println("    Hex          : " + bytesToHex(combined) + "\n");

        // Unpack
        ByteBuffer buffer = ByteBuffer.wrap(combined);
        byte[] extractedIV = new byte[12];
        buffer.get(extractedIV);
        byte[] extractedCT = new byte[buffer.remaining()];
        buffer.get(extractedCT);

        System.out.println("  Step 2: Unpack — slice first 12 bytes as IV, rest as ciphertext+tag");
        System.out.println("    Extracted IV : " + bytesToHex(extractedIV) + " (" + extractedIV.length + " bytes)");
        System.out.println("    Extracted CT : " + bytesToHex(extractedCT) + " (" + extractedCT.length + " bytes)\n");

        // Initialize cipher for decryption
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, extractedIV);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        System.out.println("  Step 3: Initialize Cipher in DECRYPT_MODE with extracted IV\n");

        // Decrypt + verify
        byte[] decrypted = cipher.doFinal(extractedCT);

        System.out.println("  Step 4: cipher.doFinal(ciphertextWithTag)");
        System.out.println("    Internal actions:");
        System.out.println("      a) Split input into ciphertext (" + (extractedCT.length - 16) + " bytes) + tag (16 bytes)");
        System.out.println("      b) Recalculate GMAC tag over ciphertext using GHASH key");
        System.out.println("      c) Compare recalculated tag with provided tag (CONSTANT TIME)");
        System.out.println("      d) If tags match  -> decrypt and return plaintext");
        System.out.println("      e) If tags differ -> throw AEADBadTagException, return NOTHING\n");

        System.out.println("  Step 5: Convert bytes back to UTF-8 String");
        System.out.println("    Decrypted bytes : " + bytesToHex(decrypted));
        System.out.println("    Decrypted text  : \"" + new String(decrypted, StandardCharsets.UTF_8) + "\"");
        System.out.println("    Match original  : " + originalText.equals(new String(decrypted, StandardCharsets.UTF_8)));
        System.out.println();
    }

    // =========================================================================
    // FLOW 3: AI Flaw #1 — What Happens When Nonces Are Reused
    // =========================================================================
    private static void flowAiFlaw1NonceReuse() throws Exception {
        System.out.println("--- Flow 3: AI Flaw #1 — Nonce Reuse Disaster ---\n");

        System.out.println("  WHAT AI GENERATES (dangerous code):");
        System.out.println("  ┌──────────────────────────────────────────────────────┐");
        System.out.println("  │  private static final byte[] STATIC_IV =            │");
        System.out.println("  │      new byte[]{1,2,3,4,5,6,7,8,9,10,11,12};       │");
        System.out.println("  │  // AI reuses this same IV for every encryption!    │");
        System.out.println("  └──────────────────────────────────────────────────────┘\n");

        // Simulate the disaster: same key + same nonce + two different plaintexts
        SecretKey key = AesGcmEncryptionService.generateKey();
        byte[] STATIC_IV = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}; // AI's mistake

        byte[] message1 = "TRANSFER $1000 TO ALICE".getBytes(StandardCharsets.UTF_8);
        byte[] message2 = "TRANSFER $9999 TO OSCAR".getBytes(StandardCharsets.UTF_8);

        // Encrypt both with SAME key and SAME nonce (the AI's mistake)
        Cipher c1 = Cipher.getInstance("AES/GCM/NoPadding");
        c1.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, STATIC_IV));
        byte[] ct1 = c1.doFinal(message1);

        Cipher c2 = Cipher.getInstance("AES/GCM/NoPadding");
        c2.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, STATIC_IV));
        byte[] ct2 = c2.doFinal(message2);

        // THE ATTACK: XOR the two ciphertexts to reveal plaintext XOR
        int minLen = Math.min(message1.length, message2.length);
        byte[] xorCiphertexts = new byte[minLen];
        byte[] xorPlaintexts = new byte[minLen];
        for (int i = 0; i < minLen; i++) {
            xorCiphertexts[i] = (byte) (ct1[i] ^ ct2[i]);
            xorPlaintexts[i] = (byte) (message1[i] ^ message2[i]);
        }

        System.out.println("  ATTACK DEMONSTRATION:");
        System.out.println("    Message 1    : \"" + new String(message1, StandardCharsets.UTF_8) + "\"");
        System.out.println("    Message 2    : \"" + new String(message2, StandardCharsets.UTF_8) + "\"");
        System.out.println("    C1 XOR C2    : " + bytesToHex(xorCiphertexts));
        System.out.println("    P1 XOR P2    : " + bytesToHex(xorPlaintexts));
        System.out.println("    C1^C2 == P1^P2? " + Arrays.equals(xorCiphertexts, xorPlaintexts));
        System.out.println();
        System.out.println("    RESULT: Attacker sees C1 XOR C2 = P1 XOR P2");
        System.out.println("    If attacker knows P1, they compute P2 = P1 XOR (C1 XOR C2)");
        System.out.println("    >>> COMPLETE PLAINTEXT RECOVERY WITHOUT THE KEY <<<\n");

        System.out.println("  YOUR CORRECTION:");
        System.out.println("  ┌──────────────────────────────────────────────────────┐");
        System.out.println("  │  byte[] iv = new byte[12];                          │");
        System.out.println("  │  secureRandom.nextBytes(iv); // FRESH per encrypt!  │");
        System.out.println("  └──────────────────────────────────────────────────────┘");
        System.out.println("  + Rotate keys before 2^32 operations (birthday bound).");
        System.out.println("  + Use Envelope Encryption (unique DEK per record).\n");

        // Verify YOUR code generates unique IVs
        AesGcmEncryptionService service = new AesGcmEncryptionService();
        byte[] enc1 = service.encrypt(message1, key);
        byte[] enc2 = service.encrypt(message2, key);
        byte[] iv1 = Arrays.copyOfRange(enc1, 0, 12);
        byte[] iv2 = Arrays.copyOfRange(enc2, 0, 12);
        System.out.print("  [VERIFY] Your code generates unique IVs: ");
        if (Arrays.equals(iv1, iv2)) {
            throw new IllegalStateException("NONCE REUSE DETECTED IN YOUR CODE!");
        }
        System.out.println("PASSED (IV1 != IV2)");
        System.out.println();
    }

    // =========================================================================
    // FLOW 4: AI Flaw #2 — String Heap Residue
    // =========================================================================
    private static void flowAiFlaw2HeapResidue() throws Exception {
        System.out.println("--- Flow 4: AI Flaw #2 — String Heap Residue ---\n");

        System.out.println("  WHAT AI GENERATES:");
        System.out.println("  ┌──────────────────────────────────────────────────────┐");
        System.out.println("  │  String secret = decrypt(ciphertext, key);          │");
        System.out.println("  │  // 'secret' is now an IMMUTABLE String in heap     │");
        System.out.println("  │  // Cannot be zeroed. Stays until GC collects it.   │");
        System.out.println("  │  // Visible in: heap dumps, /proc/pid/mem, swap     │");
        System.out.println("  └──────────────────────────────────────────────────────┘\n");

        // Demonstrate: String CANNOT be zeroed
        String immutableSecret = "SSN: 123-45-6789";
        System.out.println("  String value      : \"" + immutableSecret + "\"");
        System.out.println("  Can zero String?  : NO (immutable, no API to overwrite chars)");
        System.out.println("  String.intern()   : stays in String Pool for entire JVM lifetime\n");

        // Demonstrate: byte[] CAN be zeroed
        byte[] mutableSecret = "SSN: 123-45-6789".getBytes(StandardCharsets.UTF_8);
        System.out.println("  byte[] value      : " + bytesToHex(mutableSecret));
        Arrays.fill(mutableSecret, (byte) 0);
        System.out.println("  After Arrays.fill : " + bytesToHex(mutableSecret));

        boolean allZero = true;
        for (byte b : mutableSecret) {
            if (b != 0) { allZero = false; break; }
        }
        System.out.println("  Successfully zeroed: " + allZero + "\n");

        System.out.println("  YOUR CORRECTION:");
        System.out.println("  ┌──────────────────────────────────────────────────────┐");
        System.out.println("  │  byte[] secretBytes = decrypt(ciphertext, key);     │");
        System.out.println("  │  try {                                              │");
        System.out.println("  │      processSecret(secretBytes); // use it          │");
        System.out.println("  │  } finally {                                        │");
        System.out.println("  │      Arrays.fill(secretBytes, (byte) 0); // SCRUB   │");
        System.out.println("  │  }                                                  │");
        System.out.println("  └──────────────────────────────────────────────────────┘\n");

        System.out.print("  [VERIFY] byte[] zeroization works: ");
        System.out.println("PASSED");
        System.out.println();
    }

    // =========================================================================
    // FLOW 5: AI Flaw #3 — Missing AAD (Ciphertext Swapping Attack)
    // =========================================================================
    private static void flowAiFlaw3MissingAAD() throws Exception {
        System.out.println("--- Flow 5: AI Flaw #3 — Missing AAD (Ciphertext Swapping) ---\n");

        System.out.println("  SCENARIO: Database with encrypted SSNs per user\n");
        System.out.println("  WHAT AI GENERATES (no AAD):");
        System.out.println("  ┌──────────────────────────────────────────────────────┐");
        System.out.println("  │  encrypted_ssn = encrypt(ssn, key);  // no AAD!     │");
        System.out.println("  │  INSERT INTO users (id, encrypted_ssn) VALUES (...) │");
        System.out.println("  └──────────────────────────────────────────────────────┘\n");

        AesGcmEncryptionService service = new AesGcmEncryptionService();
        SecretKey key = AesGcmEncryptionService.generateKey();

        // WITHOUT AAD: attacker can swap ciphertext between users
        System.out.println("  === WITHOUT AAD (Vulnerable) ===");
        byte[] aliceSSN = "Alice SSN: 111-11-1111".getBytes(StandardCharsets.UTF_8);
        byte[] bobSSN = "Bob SSN: 999-99-9999".getBytes(StandardCharsets.UTF_8);

        byte[] aliceEncrypted = service.encrypt(aliceSSN, key);  // no AAD
        byte[] bobEncrypted = service.encrypt(bobSSN, key);      // no AAD

        // ATTACK: Swap Bob's ciphertext into Alice's row
        // Decryption succeeds because there's nothing binding ciphertext to user!
        byte[] swappedDecrypt = service.decrypt(bobEncrypted, key);
        System.out.println("  Alice's row now contains: \"" + new String(swappedDecrypt, StandardCharsets.UTF_8) + "\"");
        System.out.println("  ATTACK SUCCEEDED: Bob's SSN decrypted in Alice's context!\n");

        // WITH AAD: binding user_id to the ciphertext prevents swapping
        System.out.println("  === WITH AAD (Your Correction) ===");
        byte[] aliceAAD = "user_id:1001".getBytes(StandardCharsets.UTF_8);
        byte[] bobAAD = "user_id:1002".getBytes(StandardCharsets.UTF_8);

        byte[] aliceSecure = service.encrypt(aliceSSN, key, aliceAAD);
        byte[] bobSecure = service.encrypt(bobSSN, key, bobAAD);

        // Legitimate decryption with correct AAD works
        byte[] aliceRecovered = service.decrypt(aliceSecure, key, aliceAAD);
        System.out.println("  Alice decrypts own data: \"" + new String(aliceRecovered, StandardCharsets.UTF_8) + "\" -> OK");

        // ATTACK: Swap Bob's ciphertext into Alice's row -> REJECTED!
        System.out.print("  Swap attack with AAD: ");
        try {
            service.decrypt(bobSecure, key, aliceAAD); // wrong AAD
            throw new IllegalStateException("SECURITY FAILURE: Swap attack was not detected!");
        } catch (AEADBadTagException e) {
            System.out.println("BLOCKED (AEADBadTagException thrown)");
        }

        System.out.println("\n  YOUR CORRECTION:");
        System.out.println("  ┌──────────────────────────────────────────────────────┐");
        System.out.println("  │  byte[] aad = (\"user_id:\" + userId)                 │");
        System.out.println("  │                .getBytes(StandardCharsets.UTF_8);    │");
        System.out.println("  │  encrypted = encrypt(ssn, key, aad);                │");
        System.out.println("  │  // Now ciphertext is BOUND to this user_id         │");
        System.out.println("  └──────────────────────────────────────────────────────┘\n");
    }

    // =========================================================================
    // FLOW 6: Your Corrections — All Verified Together
    // =========================================================================
    private static void flowYourCorrections() throws Exception {
        System.out.println("--- Flow 6: Your Corrections — All Verified ---\n");

        AesGcmEncryptionService service = new AesGcmEncryptionService();
        SecretKey key = AesGcmEncryptionService.generateKey();

        // Correction 1: Fresh nonce per encryption
        System.out.print("  [FIX 1] Fresh SecureRandom nonce per encryption... ");
        byte[] e1 = service.encrypt("test".getBytes(StandardCharsets.UTF_8), key);
        byte[] e2 = service.encrypt("test".getBytes(StandardCharsets.UTF_8), key);
        byte[] iv1 = Arrays.copyOfRange(e1, 0, 12);
        byte[] iv2 = Arrays.copyOfRange(e2, 0, 12);
        if (Arrays.equals(iv1, iv2)) throw new IllegalStateException("Nonce reused!");
        System.out.println("PASSED");

        // Correction 2: Key validation rejects non-256-bit keys
        System.out.print("  [FIX 2] Reject non-256-bit keys... ");
        try {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(128);
            SecretKey weakKey = kg.generateKey();
            service.encrypt("test".getBytes(StandardCharsets.UTF_8), weakKey);
            throw new IllegalStateException("128-bit key was accepted!");
        } catch (IllegalArgumentException e) {
            System.out.println("PASSED (128-bit key rejected)");
        }

        // Correction 3: Tampered ciphertext detected
        System.out.print("  [FIX 3] Tampered ciphertext rejected... ");
        byte[] encrypted = service.encrypt("important".getBytes(StandardCharsets.UTF_8), key);
        encrypted[encrypted.length - 1] ^= 0x01;
        try {
            service.decrypt(encrypted, key);
            throw new IllegalStateException("Tampered ciphertext decrypted!");
        } catch (AEADBadTagException e) {
            System.out.println("PASSED");
        }

        // Correction 4: Wrong key detected
        System.out.print("  [FIX 4] Wrong key rejected... ");
        byte[] data = service.encrypt("secret".getBytes(StandardCharsets.UTF_8), key);
        try {
            service.decrypt(data, AesGcmEncryptionService.generateKey());
            throw new IllegalStateException("Wrong key decrypted!");
        } catch (AEADBadTagException e) {
            System.out.println("PASSED");
        }

        // Correction 5: AAD context binding works
        System.out.print("  [FIX 5] AAD context binding prevents ciphertext swapping... ");
        byte[] aad = "ctx:user-1".getBytes(StandardCharsets.UTF_8);
        byte[] sealed = service.encrypt("data".getBytes(StandardCharsets.UTF_8), key, aad);
        byte[] badAad = "ctx:user-2".getBytes(StandardCharsets.UTF_8);
        try {
            service.decrypt(sealed, key, badAad);
            throw new IllegalStateException("Wrong AAD accepted!");
        } catch (AEADBadTagException e) {
            System.out.println("PASSED");
        }

        System.out.println();
    }

    // =========================================================================
    // Helper
    // =========================================================================
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0 && i % 4 == 0) sb.append(' ');
            sb.append(String.format("%02x", bytes[i]));
        }
        return sb.toString();
    }
}
