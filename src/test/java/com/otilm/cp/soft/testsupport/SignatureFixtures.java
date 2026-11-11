package com.otilm.cp.soft.testsupport;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.RsaSignatureScheme;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.connector.common.v2.OperationExecutionMode;
import com.otilm.api.model.connector.cryptography.operations.SignDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.data.SignatureRequestData;
import com.otilm.api.model.connector.cryptography.v2.operations.SignDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.SignDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.SignatureAlgorithmAttribute;
import com.otilm.api.model.connector.cryptography.v2.operations.VerifyDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.data.SignatureDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.data.SignatureResponseItemV2Dto;
import com.otilm.cp.soft.attribute.RsaKeyAttributes;
import com.otilm.cp.soft.util.RequestAttributes;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Sign requests of both generations, and signatures moved from a V2 sign response into the verify request that checks
 * them.
 */
public final class SignatureFixtures {

    /** The data every fixture request signs. Each request gets its own copy. */
    private static final byte[] MESSAGE = "the message to sign".getBytes(StandardCharsets.UTF_8);

    private SignatureFixtures() {
    }

    /** The signatures as a verify request lists them, in the given order. */
    public static List<SignatureDataV2Dto> forVerification(List<SignatureResponseItemV2Dto> signatures) {
        return signatures
                .stream()
                .map(signature -> new SignatureDataV2Dto(signature.getData(), signature.getIdentifier()))
                .toList();
    }

    /** A V2 request signing one item with the addressed key. */
    public static SignDataRequestV2Dto v2Signing(List<RequestAttribute> tokenAttributes,
            List<MetadataAttribute> keyMeta, SignatureAlgorithm algorithm) {
        SignatureDataV2Dto item = new SignatureDataV2Dto();
        item.setIdentifier("one");
        item.setData(MESSAGE.clone());

        SignDataRequestV2Dto signing = new SignDataRequestV2Dto();
        signing.setTokenAttributes(tokenAttributes);
        signing.setTokenProfileAttributes(List.of());
        signing.setKeyMeta(keyMeta);
        signing.setExecutionMode(OperationExecutionMode.SYNCHRONOUS);
        signing.setSignatureAttributes(List.of(SignatureAlgorithmAttribute.request(algorithm)));
        signing.setData(List.of(item));
        return signing;
    }

    /** A V2 request verifying with the addressed key what a V2 request signed. */
    public static VerifyDataRequestV2Dto v2Verifying(SignDataRequestV2Dto signing, SignDataResponseV2Dto signed,
            List<MetadataAttribute> keyMeta) {
        VerifyDataRequestV2Dto verifying = new VerifyDataRequestV2Dto();
        verifying.setTokenAttributes(signing.getTokenAttributes());
        verifying.setTokenProfileAttributes(signing.getTokenProfileAttributes());
        verifying.setKeyMeta(keyMeta);
        verifying.setSignatureAttributes(signing.getSignatureAttributes());
        verifying.setData(signing.getData());
        verifying.setSignatures(forVerification(signed.getSignatures()));
        return verifying;
    }

    /** A V1 request signing one item with an RSA key, under PKCS#1 v1.5 over SHA-256. */
    public static SignDataRequestDto v1RsaSigning() {
        SignatureRequestData item = new SignatureRequestData();
        item.setIdentifier("one");
        item.setData(MESSAGE.clone());

        SignDataRequestDto signing = new SignDataRequestDto();
        signing
                .setSignatureAttributes(List
                        .of(RequestAttributes
                                .string(RsaKeyAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME,
                                        RsaSignatureScheme.PKCS1_v1_5.getCode()),
                                RequestAttributes
                                        .string(RsaKeyAttributes.ATTRIBUTE_DATA_SIG_DIGEST,
                                                DigestAlgorithm.SHA_256.getCode())));
        signing.setData(List.of(item));
        return signing;
    }
}
