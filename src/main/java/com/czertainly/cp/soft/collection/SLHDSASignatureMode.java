package com.czertainly.cp.soft.collection;

import com.czertainly.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContentV2;

import java.util.List;
import java.util.stream.Stream;

public enum SLHDSASignatureMode {

    FAST("f"),
    SMALL("s")
    ;

    private final String parameterName;

    SLHDSASignatureMode(String parameterName) {
        this.parameterName = parameterName;
    }

    public String getParameterName() {
        return parameterName;
    }

    public static List<BaseAttributeContentV2<?>> asStringAttributeContentList() {
        return Stream.of(values())
                .<BaseAttributeContentV2<?>>map(d -> new StringAttributeContentV2(d.name()))
                .toList();
    }
}
