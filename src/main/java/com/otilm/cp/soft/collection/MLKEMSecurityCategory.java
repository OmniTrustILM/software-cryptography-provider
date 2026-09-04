package com.otilm.cp.soft.collection;

import com.otilm.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.IntegerAttributeContentV2;
import java.util.List;
import org.springframework.lang.Nullable;

public enum MLKEMSecurityCategory {

    CATEGORY_1(1, 6400, 13056, "ML-KEM-512"),
    CATEGORY_3(3, 9472, 19200, "ML-KEM-768"),
    CATEGORY_5(5, 12544, 25344, "ML-KEM-1024");

    private static final MLKEMSecurityCategory[] VALUES;

    static {
        VALUES = values();
    }

    private final int nistSecurityCategory;
    private final int publicKeySize;
    private final int privateKeySize;
    private final String parameterSet;

    MLKEMSecurityCategory(int nistLevel, int publicKeySize, int privateKeySize, String parameterSet) {
        this.nistSecurityCategory = nistLevel;
        this.publicKeySize = publicKeySize;
        this.privateKeySize = privateKeySize;
        this.parameterSet = parameterSet;
    }

    public int getNistSecurityCategory() {
        return nistSecurityCategory;
    }

    public int getPublicKeySize() {
        return publicKeySize;
    }

    public int getPrivateKeySize() {
        return privateKeySize;
    }

    public String getParameterSet() {
        return parameterSet;
    }

    @Override
    public String toString() {
        return name();
    }

    public static MLKEMSecurityCategory valueOf(int nistLevel) {
        MLKEMSecurityCategory d = resolve(nistLevel);
        if (d == null) {
            throw new IllegalArgumentException("No matching constant for [" + nistLevel + "]");
        }
        return d;
    }

    @Nullable
    public static MLKEMSecurityCategory resolve(int nistLevel) {
        // Use cached VALUES instead of values() to prevent array allocation.
        for (MLKEMSecurityCategory d : VALUES) {
            if (d.nistSecurityCategory == nistLevel) {
                return d;
            }
        }
        return null;
    }

    public static List<BaseAttributeContentV2<?>> asIntegerAttributeContentList() {
        return List
                .of(values())
                .stream()
                .<BaseAttributeContentV2<?>>map(
                        d -> new IntegerAttributeContentV2(d.name(), d.getNistSecurityCategory()))
                .toList();
    }
}
