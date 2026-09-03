package com.otilm.cp.soft.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.HexFormat;
import java.util.stream.Collectors;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * A fingerprint of the parts of a request that decide whether a repeat is the same request.
 *
 * <p>
 * An operation identified by a caller-supplied identifier has to tell a genuine repeat, which must be answered with the
 * first result, from a different request wearing the same identifier, which the contract answers as a conflict.
 * </p>
 *
 * <p>
 * The fingerprint is stored, so it must be given only what a caller could learn anyway. A short secret hashed here
 * would be far easier to guess from the stored fingerprint than from the way the secret itself is stored, so what
 * identifies an object is passed rather than the credential that opened it.
 * </p>
 *
 * <p>
 * Two requests asking for the same thing fingerprint alike whatever order their parts arrive in. A set has no order of
 * its own and the one it iterates in can differ between runs of the same program, so a repeat arriving after a restart
 * would otherwise look like a different request.
 * </p>
 */
public final class RequestFingerprint {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);

    /** Separates the parts. A control character, so it cannot occur in what Jackson writes for a part. */
    private static final String SEPARATOR = "\u001e";

    private RequestFingerprint() {
    }

    /**
     * The fingerprint of the given parts of a request.
     *
     * @param parts the request values that decide equivalence, in a fixed order, carrying no secret
     * @return the fingerprint as hexadecimal
     */
    public static String of(Object... parts) {
        StringBuilder canonical = new StringBuilder();
        for (Object part : parts) {
            canonical.append(canonical(part)).append(SEPARATOR);
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(canonical.toString().getBytes(UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    /** Collections are written in a fixed order, so the same parts in another order read the same. */
    private static String canonical(Object part) {
        if (part instanceof Collection<?> items) {
            return items
                    .stream()
                    .map(RequestFingerprint::canonical)
                    .sorted()
                    .collect(Collectors.joining(",", "[", "]"));
        }
        try {
            return MAPPER.writeValueAsString(part);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("The request cannot be fingerprinted", e);
        }
    }
}
