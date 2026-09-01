package com.otilm.cp.soft.util;

import com.otilm.api.model.connector.cryptography.key.value.KeyValue;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

public class KeyUtil {

    private KeyUtil() {
    }

    private static final ObjectMapper ATTRIBUTES_OBJECT_MAPPER = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    public static String serializeKeyValue(KeyValue keyValue) {
        if (keyValue == null) {
            return null;
        }
        try {
            return ATTRIBUTES_OBJECT_MAPPER.writeValueAsString(keyValue);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static <T extends KeyValue> T deserializeKeyValue(String keyValue, Class<T> clazz) {
        if (keyValue == null) {
            return null;
        }
        try {
            return ATTRIBUTES_OBJECT_MAPPER.readValue(keyValue, clazz);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

}
