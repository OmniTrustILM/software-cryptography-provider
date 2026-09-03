package com.otilm.cp.soft.util;

import com.otilm.api.model.connector.cryptography.operations.data.CipherRequestData;
import com.otilm.api.model.connector.cryptography.operations.data.CipherResponseData;
import com.otilm.api.model.connector.cryptography.operations.data.SignatureRequestData;
import com.otilm.api.model.connector.cryptography.operations.data.SignatureResponseData;
import com.otilm.api.model.connector.cryptography.operations.data.VerificationResponseData;
import com.otilm.api.model.connector.cryptography.v2.operations.data.CipherDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.data.SignatureDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.data.VerificationResponseItemV2Dto;
import com.otilm.cp.soft.exception.CryptographicOperationException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Moves operation data between the two interface generations, in the shape each one states.
 *
 * <p>
 * Both carry the data itself as bytes and correlate items by the same identifier, so for the data itself only the
 * surrounding type differs. Keeping the translation here means the operations themselves are performed by one piece of
 * code for both interfaces.
 * </p>
 *
 * <p>
 * The two generations word a failed item differently, so this is also where a result becomes one the V2 contract
 * accepts. The V1 interfaces report a failed item in the item itself and leave its data unset; a V2 result item always
 * carries its outcome, and what the caller is told about a failure is this connector's own wording.
 * </p>
 */
public final class OperationDataMapper {

    private static final Logger logger = LoggerFactory.getLogger(OperationDataMapper.class);

    private static final String VERIFICATION_FAILED = "The signature could not be verified";

    private OperationDataMapper() {
    }

    public static List<SignatureRequestData> toSignatureRequests(List<SignatureDataV2Dto> data) {
        return data.stream().map(item -> {
            SignatureRequestData request = new SignatureRequestData();
            request.setIdentifier(item.getIdentifier());
            request.setData(item.getData());
            return request;
        }).toList();
    }

    /**
     * Signatures of the V2 shape. That shape carries a signature for every item the request listed, so an item that
     * could not be signed fails the whole request instead of being answered with an item that has none. Why the key
     * technology could not sign it stays in this connector's log.
     */
    public static List<SignatureDataV2Dto> toSignatureData(List<SignatureResponseData> signatures) {
        return signatures.stream().map(item -> {
            if (item.getData() == null || item.getData().length == 0) {
                logger
                        .warn("Item {} of a signing request could not be signed: {}", item.getIdentifier(),
                                item.getDetails());
                throw new CryptographicOperationException("The data could not be signed");
            }
            SignatureDataV2Dto data = new SignatureDataV2Dto();
            data.setIdentifier(item.getIdentifier());
            data.setData(item.getData());
            return data;
        }).toList();
    }

    /**
     * Signature requests of the older shape, ordered so that the older code pairs each signature with the data it was
     * made over. The V2 contract correlates the two lists by identifier, while the code performing the verification
     * pairs them by position, so signatures listed in another order would each be verified against the wrong data.
     *
     * @param data the signed data, whose order decides the pairing
     * @param signatures the signatures to verify, in whatever order the caller listed them
     * @return the signatures in the order of the signed data
     */
    public static List<SignatureRequestData> toSignatureRequestsPairedWith(List<SignatureDataV2Dto> data,
            List<SignatureDataV2Dto> signatures) {
        Map<String, SignatureDataV2Dto> byIdentifier = new HashMap<>();
        for (SignatureDataV2Dto signature : signatures) {
            if (byIdentifier.put(signature.getIdentifier(), signature) != null) {
                throw new CryptographicOperationException(
                        "More than one signature was given for item " + signature.getIdentifier());
            }
        }
        // Each signature is taken as its data item claims it, so one left over was never asked about. Answering the
        // rest would report on fewer items than the request listed, which the caller cannot tell from a full answer.
        List<SignatureDataV2Dto> paired = data.stream().map(item -> {
            SignatureDataV2Dto signature = byIdentifier.remove(item.getIdentifier());
            if (signature == null) {
                throw new CryptographicOperationException("No signature was given for item " + item.getIdentifier());
            }
            return signature;
        }).toList();
        if (!byIdentifier.isEmpty()) {
            throw new CryptographicOperationException(
                    "Signatures were given for items that were not listed: " + byIdentifier.keySet());
        }
        return toSignatureRequests(paired);
    }

    public static List<CipherRequestData> toCipherRequests(List<CipherDataV2Dto> cipherData) {
        return cipherData.stream().map(item -> {
            CipherRequestData request = new CipherRequestData();
            request.setIdentifier(item.getIdentifier());
            request.setData(item.getData());
            return request;
        }).toList();
    }

    public static List<CipherDataV2Dto> toCipherData(List<CipherResponseData> cipherData) {
        return cipherData.stream().map(item -> {
            CipherDataV2Dto data = new CipherDataV2Dto();
            data.setIdentifier(item.getIdentifier());
            data.setData(item.getData());
            return data;
        }).toList();
    }

    /**
     * A verification result of the V2 shape. An item the key technology could not verify is reported as invalid, with
     * this connector's own wording rather than the message the key technology produced: that message can quote a key or
     * an alias, and a V2 response is forwarded to the platform and logged there. The message stays in this connector's
     * own log.
     */
    public static List<VerificationResponseItemV2Dto> toVerifications(List<VerificationResponseData> verifications) {
        return verifications.stream().map(item -> {
            VerificationResponseItemV2Dto result = new VerificationResponseItemV2Dto();
            result.setIdentifier(item.getIdentifier());
            result.setResult(item.isResult());
            result.setDetails(item.getDetails() == null ? null : VERIFICATION_FAILED);
            return result;
        }).toList();
    }
}
