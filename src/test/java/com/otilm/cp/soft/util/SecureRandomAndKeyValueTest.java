package com.otilm.cp.soft.util;

import com.otilm.api.model.connector.cryptography.key.value.SpkiKeyValue;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecureRandomAndKeyValueTest {

    @BeforeAll
    static void registerProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void secureRandomIsPreparedFromAlgorithmAndProvider() {
        SecureRandom random = SecureRandomUtil.prepareSecureRandom("DEFAULT", BouncyCastleProvider.PROVIDER_NAME);
        assertNotNull(random);
        assertEquals(BouncyCastleProvider.PROVIDER_NAME, random.getProvider().getName());

        byte[] first = new byte[32];
        byte[] second = new byte[32];
        random.nextBytes(first);
        random.nextBytes(second);
        assertFalse(Arrays.equals(first, second), "two draws must not be identical");
    }

    @Test
    void unknownAlgorithmIsReported() {
        IllegalStateException thrown = assertThrows(IllegalStateException.class,
                () -> SecureRandomUtil.prepareSecureRandom("NO-SUCH-ALGORITHM", BouncyCastleProvider.PROVIDER_NAME));
        assertTrue(thrown.getMessage().contains("NO-SUCH-ALGORITHM"));
    }

    @Test
    void unknownProviderIsReported() {
        IllegalStateException thrown = assertThrows(IllegalStateException.class,
                () -> SecureRandomUtil.prepareSecureRandom("DEFAULT", "NO-SUCH-PROVIDER"));
        assertTrue(thrown.getMessage().contains("NO-SUCH-PROVIDER"));
    }

    @Test
    void keyValueSerializationRoundTrips() {
        SpkiKeyValue original = new SpkiKeyValue("bWF0ZXJpYWw=");

        String serialized = KeyUtil.serializeKeyValue(original);
        assertNotNull(serialized);

        SpkiKeyValue restored = KeyUtil.deserializeKeyValue(serialized, SpkiKeyValue.class);
        assertEquals(original.getValue(), restored.getValue());
    }

    @Test
    void nullKeyValueSerializesAndDeserializesToNull() {
        assertNull(KeyUtil.serializeKeyValue(null));
        assertNull(KeyUtil.deserializeKeyValue(null, SpkiKeyValue.class));
    }

    @Test
    void unknownPropertiesAreIgnoredOnDeserialization() {
        // The mapper is configured to tolerate unknown fields so a value written by a newer
        // release still loads.
        SpkiKeyValue restored = KeyUtil
                .deserializeKeyValue("{\"value\":\"bWF0ZXJpYWw=\",\"unexpected\":\"ignored\"}", SpkiKeyValue.class);
        assertEquals("bWF0ZXJpYWw=", restored.getValue());
    }

    @Test
    void malformedKeyValueIsRejected() {
        assertThrows(IllegalStateException.class,
                () -> KeyUtil.deserializeKeyValue("this is not json", SpkiKeyValue.class));
    }
}
