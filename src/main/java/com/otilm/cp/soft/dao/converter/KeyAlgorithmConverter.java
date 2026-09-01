package com.otilm.cp.soft.dao.converter;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

@Converter(autoApply = true)
public class KeyAlgorithmConverter implements AttributeConverter<KeyAlgorithm, String> {

    @Override
    public String convertToDatabaseColumn(KeyAlgorithm keyAlgorithm) {
        if (keyAlgorithm == null) {
            return null;
        }
        return keyAlgorithm.name();
    }

    @Override
    public KeyAlgorithm convertToEntityAttribute(String keyAlgorithm) {
        if (keyAlgorithm == null) {
            return null;
        }
        return KeyAlgorithm.valueOf(keyAlgorithm);
    }

}
