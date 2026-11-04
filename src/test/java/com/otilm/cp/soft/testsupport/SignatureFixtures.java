package com.otilm.cp.soft.testsupport;

import com.otilm.api.model.connector.cryptography.v2.operations.data.SignatureDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.data.SignatureResponseItemV2Dto;
import java.util.List;

/**
 * Signatures moved from a V2 sign response into the verify request that checks them.
 */
public final class SignatureFixtures {

    private SignatureFixtures() {
    }

    /** The signatures as a verify request lists them, in the given order. */
    public static List<SignatureDataV2Dto> forVerification(List<SignatureResponseItemV2Dto> signatures) {
        return signatures
                .stream()
                .map(signature -> new SignatureDataV2Dto(signature.getData(), signature.getIdentifier()))
                .toList();
    }
}
