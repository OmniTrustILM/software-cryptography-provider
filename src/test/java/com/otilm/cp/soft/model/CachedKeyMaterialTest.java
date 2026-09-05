package com.otilm.cp.soft.model;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** What the cached material may say about itself, which is the aliases it holds and never the code. */
class CachedKeyMaterialTest {

    private static final String CODE = "0p3n-s3sam3";

    private static final Timestamp VERSION = Timestamp.from(Instant.EPOCH);

    /**
     * A cached value reaches a log line through nothing more than being printed, and the redaction every line passes
     * through takes a secret out by the name it was written under — which the name a record prints its own components
     * by is not.
     */
    @Test
    void saysNothingAboutTheCodeItWasOpenedWith() {
        // given
        CachedKeyMaterial material = new CachedKeyMaterial(Map.of(), Map.of(), CODE, VERSION);

        // when
        String said = material.toString();

        // then
        assertFalse(said.contains(CODE), () -> "the code leaked into " + said);
    }

    /** It still has to say which keys it holds, which is what it is printed for. */
    @Test
    void saysWhichKeysItHolds() {
        // given
        CachedKeyMaterial material = new CachedKeyMaterial(Map.of("signing", new StubPrivateKey()), Map.of(), CODE,
                VERSION);

        // when
        String said = material.toString();

        // then
        assertTrue(said.contains("signing"), () -> "the aliases are missing from " + said);
    }

    private static final class StubPrivateKey implements java.security.PrivateKey {

        private static final long serialVersionUID = 1L;

        @Override
        public String getAlgorithm() {
            return "stub";
        }

        @Override
        public String getFormat() {
            return "stub";
        }

        @Override
        public byte[] getEncoded() {
            return new byte[0];
        }
    }
}
