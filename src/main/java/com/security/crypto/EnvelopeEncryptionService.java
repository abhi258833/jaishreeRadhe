package com.security.crypto;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/**
 * Demonstrates the Envelope Encryption pattern (KEK / DEK architecture).
 *
 * This is the industry-standard key management strategy used by:
 *   - AWS KMS, GCP Cloud KMS, Azure Key Vault
 *   - HashiCorp Vault
 *   - Any FIPS 140-2 compliant system
 *
 * Architecture:
 *   ┌──────────────────────────────────────────────────────────┐
 *   │  KMS / HSM (Hardware Security Module)                   │
 *   │  ┌───────────────────────────────────────────────┐      │
 *   │  │  KEK (Key Encryption Key) — NEVER LEAVES HSM  │      │
 *   │  └───────────────────────────────────────────────┘      │
 *   └───────────────────────────────────┬──────────────────────┘
 *                                       │ wraps / unwraps
 *                                       ▼
 *   ┌──────────────────────────────────────────────────────────┐
 *   │  Application Layer                                       │
 *   │  ┌──────────────────────────────────────────────┐       │
 *   │  │  DEK (Data Encryption Key) — per record/file  │       │
 *   │  │  Encrypted DEK stored alongside ciphertext    │       │
 *   │  └──────────────────────────────────────────────┘       │
 *   │  ┌──────────────────────────────────────────────┐       │
 *   │  │  Ciphertext = AES-256-GCM(plaintext, DEK)    │       │
 *   │  └──────────────────────────────────────────────┘       │
 *   └──────────────────────────────────────────────────────────┘
 *
 * Benefits:
 *   1. Key Isolation: KEK never touches plaintext data.
 *   2. Scalability: Each record gets its own DEK — compromising one DEK exposes only one record.
 *   3. Fast Key Rotation: Rotating the KEK re-wraps all DEKs without re-encrypting all data.
 *   4. Nonce Safety: Each DEK is used for very few encryptions, keeping nonce reuse probability near zero.
 */
public final class EnvelopeEncryptionService {

    private final AesGcmEncryptionService cryptoService;

    public EnvelopeEncryptionService() {
        this.cryptoService = new AesGcmEncryptionService();
    }

    /**
     * An Envelope: contains the encrypted DEK and the data ciphertext.
     *
     * Wire format (all concatenated):
     *   [4 bytes: encrypted DEK length][encrypted DEK bytes][data ciphertext bytes]
     */
    public record Envelope(byte[] encryptedDek, byte[] dataCiphertext) {

        public Envelope {
            Objects.requireNonNull(encryptedDek, "Encrypted DEK must not be null");
            Objects.requireNonNull(dataCiphertext, "Data ciphertext must not be null");
            encryptedDek = encryptedDek.clone();
            dataCiphertext = dataCiphertext.clone();
        }

        @Override public byte[] encryptedDek() { return encryptedDek.clone(); }
        @Override public byte[] dataCiphertext() { return dataCiphertext.clone(); }

        /** Serialize to a single byte array for storage. */
        public byte[] toBytes() {
            ByteBuffer buffer = ByteBuffer.allocate(4 + encryptedDek.length + dataCiphertext.length);
            buffer.putInt(encryptedDek.length);
            buffer.put(encryptedDek);
            buffer.put(dataCiphertext);
            return buffer.array();
        }

        /** Deserialize from a single byte array. */
        public static Envelope fromBytes(byte[] data) {
            ByteBuffer buffer = ByteBuffer.wrap(data);
            int dekLen = buffer.getInt();
            byte[] encDek = new byte[dekLen];
            buffer.get(encDek);
            byte[] ct = new byte[buffer.remaining()];
            buffer.get(ct);
            return new Envelope(encDek, ct);
        }

        /** Base64 for JSON/REST transport. */
        public String toBase64() {
            return Base64.getEncoder().encodeToString(toBytes());
        }

        public static Envelope fromBase64(String b64) {
            return fromBytes(Base64.getDecoder().decode(b64));
        }
    }

    /**
     * Encrypts plaintext using Envelope Encryption.
     *
     * Steps:
     *   1. Generate a fresh, random DEK (Data Encryption Key).
     *   2. Encrypt the plaintext with the DEK using AES-256-GCM.
     *   3. Encrypt (wrap) the DEK itself with the KEK using AES-256-GCM.
     *   4. Bundle the encrypted DEK + data ciphertext into an Envelope.
     *   5. Zero out the plaintext DEK from memory immediately.
     *
     * @param plaintext The data to protect.
     * @param kek       The Key Encryption Key (master key from KMS/HSM).
     * @return Sealed Envelope containing encrypted DEK and data ciphertext.
     */
    public Envelope seal(byte[] plaintext, SecretKey kek) throws GeneralSecurityException {
        Objects.requireNonNull(plaintext, "Plaintext must not be null");

        // Step 1: Generate a fresh DEK for this specific record/file
        SecretKey dek = AesGcmEncryptionService.generateKey();

        // Step 2: Encrypt the actual data with the DEK
        byte[] dataCiphertext = cryptoService.encrypt(plaintext, dek);

        // Step 3: Wrap (encrypt) the DEK with the KEK
        byte[] dekBytes = dek.getEncoded();
        byte[] encryptedDek = cryptoService.encrypt(dekBytes, kek);

        // Step 5: Zero out the plaintext DEK bytes from memory immediately
        Arrays.fill(dekBytes, (byte) 0);

        // Step 4: Bundle into an Envelope
        return new Envelope(encryptedDek, dataCiphertext);
    }

    /**
     * Decrypts an Envelope using Envelope Decryption.
     *
     * Steps:
     *   1. Unwrap (decrypt) the DEK using the KEK.
     *   2. Reconstruct the DEK as a SecretKey.
     *   3. Decrypt the data ciphertext with the DEK.
     *   4. Zero out the plaintext DEK from memory.
     *
     * @param envelope The sealed envelope.
     * @param kek      The Key Encryption Key (master key from KMS/HSM).
     * @return The original plaintext.
     */
    public byte[] unseal(Envelope envelope, SecretKey kek) throws GeneralSecurityException {
        Objects.requireNonNull(envelope, "Envelope must not be null");

        // Step 1: Unwrap the DEK using the KEK
        byte[] dekBytes = cryptoService.decrypt(envelope.encryptedDek(), kek);

        // Step 2: Reconstruct the DEK
        SecretKey dek = new javax.crypto.spec.SecretKeySpec(dekBytes, "AES");

        // Step 4: Zero out plaintext DEK bytes
        Arrays.fill(dekBytes, (byte) 0);

        // Step 3: Decrypt the data
        return cryptoService.decrypt(envelope.dataCiphertext(), dek);
    }

    /**
     * Rotates the KEK without re-encrypting all data.
     *
     * This is the key rotation magic:
     *   1. Unwrap the DEK using the OLD KEK.
     *   2. Re-wrap the same DEK using the NEW KEK.
     *   3. The data ciphertext remains completely unchanged.
     *
     * Cost: O(1) per record — only the small DEK (32 bytes) is re-encrypted,
     *       NOT the potentially gigabyte-sized data payload.
     *
     * @param envelope The existing envelope sealed with the old KEK.
     * @param oldKek   The current/old Key Encryption Key.
     * @param newKek   The new Key Encryption Key to rotate to.
     * @return A new Envelope with the DEK re-wrapped under the new KEK.
     */
    public Envelope rotateKek(Envelope envelope, SecretKey oldKek, SecretKey newKek)
            throws GeneralSecurityException {
        Objects.requireNonNull(envelope, "Envelope must not be null");

        // Step 1: Unwrap DEK with old KEK
        byte[] dekBytes = cryptoService.decrypt(envelope.encryptedDek(), oldKek);

        // Step 2: Re-wrap DEK with new KEK
        byte[] reEncryptedDek = cryptoService.encrypt(dekBytes, newKek);

        // Step 3: Zero plaintext DEK
        Arrays.fill(dekBytes, (byte) 0);

        // Data ciphertext is UNCHANGED — no re-encryption of actual data needed!
        return new Envelope(reEncryptedDek, envelope.dataCiphertext());
    }
}
