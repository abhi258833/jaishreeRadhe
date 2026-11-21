package com.security.crypto;

import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.Objects;

/**
 * Immutable carrier for AES-GCM encrypted payload consisting of:
 * - 12-byte Nonce / Initialization Vector (IV)
 * - Ciphertext concatenated with the 128-bit (16-byte) Authentication Tag.
 */
public record EncryptedPayload(byte[] iv, byte[] ciphertextWithTag) {

    public static final int IV_LENGTH_BYTES = 12;
    public static final int TAG_LENGTH_BYTES = 16;
    public static final int MIN_PAYLOAD_BYTES = IV_LENGTH_BYTES + TAG_LENGTH_BYTES;

    public EncryptedPayload {
        Objects.requireNonNull(iv, "IV must not be null");
        Objects.requireNonNull(ciphertextWithTag, "Ciphertext must not be null");

        if (iv.length != IV_LENGTH_BYTES) {
            throw new IllegalArgumentException("IV must be exactly " + IV_LENGTH_BYTES + " bytes, but was " + iv.length);
        }
        if (ciphertextWithTag.length < TAG_LENGTH_BYTES) {
            throw new IllegalArgumentException("Ciphertext payload must contain at least " + TAG_LENGTH_BYTES + " bytes for the authentication tag.");
        }

        // Defensive copy to guarantee immutability
        iv = iv.clone();
        ciphertextWithTag = ciphertextWithTag.clone();
    }

    @Override
    public byte[] iv() {
        return iv.clone();
    }

    @Override
    public byte[] ciphertextWithTag() {
        return ciphertextWithTag.clone();
    }

    /**
     * Serializes this payload into a single binary array: [IV (12 bytes)][Ciphertext + Tag].
     *
     * @return combined binary payload.
     */
    public byte[] toCombinedBytes() {
        byte[] combined = new byte[iv.length + ciphertextWithTag.length];
        ByteBuffer buffer = ByteBuffer.wrap(combined);
        buffer.put(iv);
        buffer.put(ciphertextWithTag);
        return combined;
    }

    /**
     * Reconstructs an EncryptedPayload from a combined binary array: [IV (12 bytes)][Ciphertext + Tag].
     *
     * @param combined combined binary payload.
     * @return deserialized EncryptedPayload.
     */
    public static EncryptedPayload fromCombinedBytes(byte[] combined) {
        Objects.requireNonNull(combined, "Combined payload must not be null");
        if (combined.length < MIN_PAYLOAD_BYTES) {
            throw new IllegalArgumentException("Invalid payload length: expected at least " + MIN_PAYLOAD_BYTES + " bytes, but received " + combined.length);
        }

        ByteBuffer buffer = ByteBuffer.wrap(combined);
        byte[] iv = new byte[IV_LENGTH_BYTES];
        buffer.get(iv);

        byte[] ciphertextWithTag = new byte[buffer.remaining()];
        buffer.get(ciphertextWithTag);

        return new EncryptedPayload(iv, ciphertextWithTag);
    }

    /**
     * Serializes to standard Base64 string for safe ASCII transport (e.g., JSON, HTTP headers).
     */
    public String toBase64() {
        return Base64.getEncoder().encodeToString(toCombinedBytes());
    }

    /**
     * Deserializes an EncryptedPayload from a standard Base64 string.
     */
    public static EncryptedPayload fromBase64(String base64) {
        Objects.requireNonNull(base64, "Base64 payload must not be null");
        byte[] combined = Base64.getDecoder().decode(base64);
        return fromCombinedBytes(combined);
    }
}
