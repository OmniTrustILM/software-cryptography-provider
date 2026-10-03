package com.otilm.cp.soft.util;

/**
 * Declares byte sizes for minimum PKCS#1 v1.5 padding, fixed OAEP and PSS overhead, and DigestInfo prefixes.
 */
public final class RsaEncodingConstants {

    /**
     * Minimum PKCS#1 v1.5 padding overhead for encryption and signature encodings.
     */
    public static final int PKCS1_V1_5_PADDING_BYTES = 11;

    /**
     * Fixed OAEP overhead in addition to twice the digest length.
     */
    public static final int OAEP_PADDING_BYTES = 2;

    /**
     * DER DigestInfo prefix length for SHA-256, SHA-384, and SHA-512 signatures.
     */
    public static final int DIGEST_INFO_PREFIX_BYTES = 19;

    /**
     * Fixed PSS encoding overhead in addition to the digest and salt.
     */
    public static final int PSS_PADDING_BYTES = 2;

    private RsaEncodingConstants() {
    }
}
