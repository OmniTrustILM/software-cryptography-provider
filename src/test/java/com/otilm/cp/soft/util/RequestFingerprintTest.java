package com.otilm.cp.soft.util;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The fingerprint decides whether a repeated request is the same request, so it has to be stable across attempts and
 * has to change when any part of the request does.
 */
class RequestFingerprintTest {

    @Test
    void theSameRequestFingerprintsTheSameWay() {
        // given
        // when
        String first = RequestFingerprint.of("keyPair", "synchronous", List.of("a", "b"));
        String second = RequestFingerprint.of("keyPair", "synchronous", List.of("a", "b"));

        // then
        assertEquals(first, second);
    }

    @Test
    void aDifferentRequestFingerprintsDifferently() {
        // given
        String original = RequestFingerprint.of("keyPair", "synchronous", List.of("a", "b"));

        // when
        // then
        assertNotEquals(original, RequestFingerprint.of("keyPair", "synchronous", List.of("a", "c")));
        assertNotEquals(original, RequestFingerprint.of("secret", "synchronous", List.of("a", "b")));
    }

    /** A request carries attributes as maps, whose iteration order must not decide the answer. */
    @Test
    void theOrderTheSameValuesArriveInDoesNotMatter() {
        // given
        Map<String, String> one = Map.of("alias", "key", "algorithm", "RSA");
        Map<String, String> other = Map.of("algorithm", "RSA", "alias", "key");

        // when
        // then
        assertEquals(RequestFingerprint.of(one), RequestFingerprint.of(other));
    }

    /**
     * Key usages arrive as a set, which has no order of its own. The one a set iterates in can differ between runs of
     * the same program, so a repeat arriving after a restart would otherwise look like a different request.
     */
    @Test
    void theOrderASetIteratesInDoesNotMatter() {
        // given
        Set<String> one = new LinkedHashSet<>(List.of("SIGN", "VERIFY"));
        Set<String> other = new LinkedHashSet<>(List.of("VERIFY", "SIGN"));

        // when
        // then
        assertEquals(RequestFingerprint.of(one), RequestFingerprint.of(other));
    }

    /** A list of attributes says the same thing whichever order they were written in. */
    @Test
    void theOrderAListCarriesTheSameItemsInDoesNotMatter() {
        // given
        List<Map<String, String>> one = List.of(Map.of("name", "alias"), Map.of("name", "algorithm"));
        List<Map<String, String>> other = List.of(Map.of("name", "algorithm"), Map.of("name", "alias"));

        // when
        // then
        assertEquals(RequestFingerprint.of(one), RequestFingerprint.of(other));
    }

    /** Items differing in more than order are still a different request. */
    @Test
    void aListWithADifferentItemFingerprintsDifferently() {
        // given
        List<String> one = List.of("alias", "algorithm");
        List<String> other = List.of("alias", "keySize");

        // when
        // then
        assertNotEquals(RequestFingerprint.of(one), RequestFingerprint.of(other));
    }

    @Test
    void aFingerprintIsHexadecimalAndFixedLength() {
        // given
        // when
        String fingerprint = RequestFingerprint.of("keyPair");

        // then
        assertEquals(64, fingerprint.length());
        assertTrue(fingerprint.matches("[0-9a-f]{64}"), fingerprint);
    }

    /** Anything the fingerprint cannot read is a request this connector cannot accept, not a silent match. */
    @Test
    void refusesAValueItCannotRead() {
        // given
        Object unreadable = new Object() {

            @SuppressWarnings("unused")
            public String getValue() {
                throw new IllegalStateException("not readable");
            }
        };

        // when
        // then
        assertThrows(IllegalArgumentException.class, () -> RequestFingerprint.of(unreadable));
    }

    @Test
    void absentPartsAreStillFingerprinted() {
        // given
        // when
        String fingerprint = RequestFingerprint.of("keyPair", null, List.of());

        // then
        assertNotEquals(RequestFingerprint.of("keyPair", "synchronous", List.of()), fingerprint);
    }
}
