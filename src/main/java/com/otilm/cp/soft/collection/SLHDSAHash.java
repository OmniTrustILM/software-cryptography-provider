package com.otilm.cp.soft.collection;

import com.otilm.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;

import java.util.List;
import java.util.stream.Stream;

public enum SLHDSAHash {
    SHA2("SHA2"),
    SHAKE256("SHAKE");

    private static final SLHDSAHash[] VALUES;

    static {
        VALUES = values();
    }

    private final String hashName;

    SLHDSAHash(String hashName) {
        this.hashName = hashName;
    }

    public String getHashName() {
        return hashName;
    }

    @Override
    public String toString() {
        return name();
    }

    public static List<BaseAttributeContentV2<?>> asStringAttributeContentList() {
        return Stream
                .of(values())
                .<BaseAttributeContentV2<?>>map(d -> new StringAttributeContentV2(d.name(), d.getHashName()))
                .toList();
    }
}
