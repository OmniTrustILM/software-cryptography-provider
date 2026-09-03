package com.otilm.cp.soft.util;

import com.otilm.api.model.connector.cryptography.operations.data.CipherResponseData;
import com.otilm.api.model.connector.cryptography.operations.data.SignatureRequestData;
import com.otilm.api.model.connector.cryptography.operations.data.SignatureResponseData;
import com.otilm.api.model.connector.cryptography.operations.data.VerificationResponseData;
import com.otilm.api.model.connector.cryptography.v2.operations.data.CipherDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.data.SignatureDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.data.VerificationResponseItemV2Dto;
import com.otilm.cp.soft.exception.CryptographicOperationException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The V2 interfaces require every result item to carry the identifier the request gave it and to state its outcome, so
 * this is where a result of the older shape becomes one the V2 contract accepts.
 */
class OperationDataMapperTest {

    private static final byte[] DATA = "signed".getBytes(StandardCharsets.UTF_8);

    private static final byte[] OTHER = "also signed".getBytes(StandardCharsets.UTF_8);

    /** The identifier is the only thing pairing a result with the item it came from, so it cannot be dropped. */
    @Test
    void everySignatureKeepsTheIdentifierOfTheItemItSigned() {
        // given
        List<SignatureResponseData> signatures = List.of(signature("first", DATA), signature("second", DATA));

        // when
        List<SignatureDataV2Dto> mapped = OperationDataMapper.toSignatureData(signatures);

        // then
        assertEquals(List.of("first", "second"), mapped.stream().map(SignatureDataV2Dto::getIdentifier).toList());
        assertArrayEquals(DATA, mapped.get(0).getData());
    }

    @Test
    void everyCipherResultKeepsTheIdentifierOfTheItemItProcessed() {
        // given
        List<CipherResponseData> processed = List.of(cipher("first", DATA), cipher("second", DATA));

        // when
        List<CipherDataV2Dto> mapped = OperationDataMapper.toCipherData(processed);

        // then
        assertEquals(List.of("first", "second"), mapped.stream().map(CipherDataV2Dto::getIdentifier).toList());
        assertArrayEquals(DATA, mapped.get(1).getData());
    }

    /**
     * A V2 signing response carries a signature for every item the request listed. An item the key technology could not
     * sign has none, so answering with it would be a response the contract rejects.
     */
    @Test
    void anItemThatCouldNotBeSignedFailsTheRequest() {
        // given
        SignatureResponseData failed = new SignatureResponseData();
        failed.setIdentifier("first");
        failed.setDetails("Signature failed: the key is not usable");
        List<SignatureResponseData> signatures = List.of(failed);

        // when
        // then
        assertThrows(CryptographicOperationException.class, () -> OperationDataMapper.toSignatureData(signatures));
    }

    @Test
    void anItemSignedWithNothingFailsTheRequest() {
        // given
        List<SignatureResponseData> signatures = List.of(signature("first", new byte[0]));

        // when
        // then
        assertThrows(CryptographicOperationException.class, () -> OperationDataMapper.toSignatureData(signatures));
    }

    /**
     * A message from the key technology can quote a key or an alias, and a V2 response is forwarded to the platform and
     * logged there, so the caller is told this connector's own wording.
     */
    @Test
    void aFailedVerificationDoesNotEchoTheFailureMessage() {
        // given
        VerificationResponseData failed = new VerificationResponseData();
        failed.setIdentifier("first");
        failed.setResult(false);
        failed.setDetails("Verification failed: bad signature for key alias secret-key-1");

        // when
        List<VerificationResponseItemV2Dto> mapped = OperationDataMapper.toVerifications(List.of(failed));

        // then
        String details = String.valueOf(mapped.get(0).getDetails());
        assertFalse(details.contains("secret-key-1"), () -> "the failure message leaked into " + details);
        assertTrue(details.contains("could not be verified"), details);
        assertFalse(mapped.get(0).getResult(), "an item that could not be verified is not valid");
        assertEquals("first", mapped.get(0).getIdentifier());
    }

    @Test
    void aVerificationThatSucceededCarriesNoDetails() {
        // given
        VerificationResponseData verified = new VerificationResponseData();
        verified.setIdentifier("first");
        verified.setResult(true);

        // when
        List<VerificationResponseItemV2Dto> mapped = OperationDataMapper.toVerifications(List.of(verified));

        // then
        assertNull(mapped.get(0).getDetails());
        assertTrue(mapped.get(0).getResult());
    }

    /** The order the caller listed the signatures in must not decide which data each one is checked against. */
    @Test
    void pairsEachSignatureWithTheDataOfTheSameIdentifier() {
        // given
        List<SignatureDataV2Dto> data = List.of(item("one", DATA), item("two", OTHER));
        List<SignatureDataV2Dto> signatures = List.of(item("two", OTHER), item("one", DATA));

        // when
        List<SignatureRequestData> paired = OperationDataMapper.toSignatureRequestsPairedWith(data, signatures);

        // then
        assertEquals(List.of("one", "two"), paired.stream().map(SignatureRequestData::getIdentifier).toList());
        assertArrayEquals(DATA, paired.get(0).getData());
    }

    @Test
    void refusesDataThatWasGivenNoSignature() {
        // given
        List<SignatureDataV2Dto> data = List.of(item("one", DATA), item("two", OTHER));
        List<SignatureDataV2Dto> signatures = List.of(item("one", DATA));

        // when
        // then
        assertThrows(CryptographicOperationException.class,
                () -> OperationDataMapper.toSignatureRequestsPairedWith(data, signatures));
    }

    @Test
    void refusesTwoSignaturesWearingOneIdentifier() {
        // given
        List<SignatureDataV2Dto> data = List.of(item("one", DATA));
        List<SignatureDataV2Dto> signatures = List.of(item("one", DATA), item("one", OTHER));

        // when
        // then
        assertThrows(CryptographicOperationException.class,
                () -> OperationDataMapper.toSignatureRequestsPairedWith(data, signatures));
    }

    /**
     * A signature no data item claims was never asked about. Verifying only the items that were listed would report on
     * fewer of them than the caller sent, which it cannot tell from a full answer.
     */
    @Test
    void refusesASignatureForAnItemThatWasNotListed() {
        // given
        List<SignatureDataV2Dto> data = List.of(item("one", DATA));
        List<SignatureDataV2Dto> signatures = List.of(item("one", DATA), item("two", OTHER));

        // when
        // then
        assertThrows(CryptographicOperationException.class,
                () -> OperationDataMapper.toSignatureRequestsPairedWith(data, signatures));
    }

    /** Two data items wearing one identifier would consume the same signature twice. */
    @Test
    void refusesTwoDataItemsWearingOneIdentifier() {
        // given
        List<SignatureDataV2Dto> data = List.of(item("one", DATA), item("one", OTHER));
        List<SignatureDataV2Dto> signatures = List.of(item("one", DATA), item("two", OTHER));

        // when
        // then
        assertThrows(CryptographicOperationException.class,
                () -> OperationDataMapper.toSignatureRequestsPairedWith(data, signatures));
    }

    private static SignatureDataV2Dto item(String identifier, byte[] data) {
        SignatureDataV2Dto item = new SignatureDataV2Dto();
        item.setIdentifier(identifier);
        item.setData(data);
        return item;
    }

    private static SignatureResponseData signature(String identifier, byte[] data) {
        SignatureResponseData signature = new SignatureResponseData();
        signature.setIdentifier(identifier);
        signature.setData(data);
        return signature;
    }

    private static CipherResponseData cipher(String identifier, byte[] data) {
        CipherResponseData processed = new CipherResponseData();
        processed.setIdentifier(identifier);
        processed.setData(data);
        return processed;
    }
}
