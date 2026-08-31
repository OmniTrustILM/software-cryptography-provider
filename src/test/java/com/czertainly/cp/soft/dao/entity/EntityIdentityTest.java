package com.czertainly.cp.soft.dao.entity;

import com.czertainly.api.model.common.enums.cryptography.KeyFormat;
import com.czertainly.api.model.connector.cryptography.key.value.CustomKeyValue;
import com.czertainly.api.model.connector.cryptography.key.value.EprkiKeyValue;
import com.czertainly.api.model.connector.cryptography.key.value.KeyValue;
import com.czertainly.api.model.connector.cryptography.key.value.PrkiKeyValue;
import com.czertainly.api.model.connector.cryptography.key.value.RawKeyValue;
import com.czertainly.api.model.connector.cryptography.key.value.SpkiKeyValue;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.UUID;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Entity identity and key value serialization. Both entities compare on UUID alone, so two
 * rows loaded separately for the same key are the same entity to the persistence context.
 */
class EntityIdentityTest {

    private static final UUID UUID_A = UUID.fromString("11111111-1111-1111-1111-111111111111");
    private static final UUID UUID_B = UUID.fromString("22222222-2222-2222-2222-222222222222");

    private static KeyData keyData(UUID uuid, String name) {
        KeyData key = new KeyData();
        key.setUuid(uuid);
        key.setName(name);
        return key;
    }

    private static TokenInstance tokenInstance(UUID uuid, String name) {
        TokenInstance token = new TokenInstance();
        token.setUuid(uuid);
        token.setName(name);
        return token;
    }

    @Test
    void keyDataComparesOnUuidAloneAndIgnoresOtherFields() {
        KeyData first = keyData(UUID_A, "one");
        KeyData second = keyData(UUID_A, "a different name");

        assertEquals(first, second, "the same UUID is the same key regardless of other fields");
        assertEquals(first.hashCode(), second.hashCode());
        assertNotEquals(first, keyData(UUID_B, "one"));
        assertEqualsContract(first);
    }

    @Test
    void tokenInstanceComparesOnUuidAloneAndIgnoresOtherFields() {
        TokenInstance first = tokenInstance(UUID_A, "one");
        TokenInstance second = tokenInstance(UUID_A, "a different name");

        assertEquals(first, second);
        assertEquals(first.hashCode(), second.hashCode());
        assertNotEquals(first, tokenInstance(UUID_B, "one"));
        assertEqualsContract(first);
    }

    /**
     * The reflexive, null and foreign-type branches of {@code equals}.
     *
     * <p>Called through {@code equals} rather than through the assertion helpers: those
     * helpers delegate to the very method being tested, which both obscures the intent and
     * cannot express "not equal to a value of another type" without comparing dissimilar
     * types.</p>
     */
    @SuppressWarnings("java:S5785")
    private static void assertEqualsContract(Object entity) {
        assertTrue(entity.equals(entity), "equality must be reflexive");
        assertFalse(entity.equals(null), "an entity is never equal to null");
        assertFalse(entity.equals("a value of another type"), "an entity is never equal to another type");
    }

    private static Stream<Arguments> keyFormats() {
        return Stream.of(
                Arguments.of(KeyFormat.RAW, new RawKeyValue("cmF3"), RawKeyValue.class),
                Arguments.of(KeyFormat.SPKI, new SpkiKeyValue("c3BraQ=="), SpkiKeyValue.class),
                Arguments.of(KeyFormat.PRKI, new PrkiKeyValue("cHJraQ=="), PrkiKeyValue.class),
                Arguments.of(KeyFormat.EPRKI, new EprkiKeyValue("ZXBya2k="), EprkiKeyValue.class),
                Arguments.of(KeyFormat.CUSTOM, new CustomKeyValue(), CustomKeyValue.class)
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("keyFormats")
    void keyValueIsReadBackAsTheTypeTheFormatDeclares(KeyFormat format, KeyValue value, Class<?> expected) {
        KeyData key = keyData(UUID_A, "key");
        key.setFormat(format);
        key.setValue(value);

        // The stored column is format-agnostic JSON; the format column decides how it is read.
        assertInstanceOf(expected, key.getValue());
    }

    @Test
    void anUnsetFormatCannotBeRead() {
        KeyData key = keyData(UUID_A, "key");
        key.setFormat(null);
        key.setValue(new SpkiKeyValue("c3BraQ=="));

        assertThrows(NullPointerException.class, key::getValue);
    }

    @Test
    void tokenInstanceUuidIsCarriedAlongsideTheRelation() {
        KeyData key = keyData(UUID_A, "key");
        TokenInstance token = tokenInstance(UUID_B, "token");

        key.setTokenInstance(token);
        key.setTokenInstanceUuid(UUID_B);

        assertEquals(token, key.getTokenInstance());
        assertEquals(UUID_B, key.getTokenInstanceUuid());
    }
}
