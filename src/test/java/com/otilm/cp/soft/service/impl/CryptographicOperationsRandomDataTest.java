package com.otilm.cp.soft.service.impl;

import com.otilm.api.model.connector.cryptography.operations.RandomDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.RandomDataResponseDto;
import jakarta.transaction.Transactional;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
@Transactional
class CryptographicOperationsRandomDataTest extends AbstractCryptographicOperationsTest {

    @ParameterizedTest(name = "{0} bytes")
    @ValueSource(ints = {16, 32, 64, 256})
    void testRandomData(int requestedLength) {
        RandomDataRequestDto request = new RandomDataRequestDto();
        request.setLength(requestedLength);

        RandomDataResponseDto response = cryptographicOperationsService
                .randomData(tokenInstance.getUuid().toString(), request);

        Assertions.assertNotNull(response, "Response should not be null");
        Assertions.assertNotNull(response.getData(), "Response data should not be null");
        Assertions
                .assertEquals(requestedLength, response.getData().length, "Data length should match requested length");
        Assertions
                .assertFalse(isAllZeros(response.getData()),
                        "Data should not be all zeros (probabilistic sanity check)");
    }

    private boolean isAllZeros(byte[] data) {
        for (byte b : data) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }
}
