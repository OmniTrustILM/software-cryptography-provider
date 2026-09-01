package com.otilm.cp.soft;

import com.otilm.cp.soft.dto.ApiErrorResponseDto;
import com.otilm.cp.soft.exception.CryptographicOperationException;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class ExceptionHandlingAdviceTest {

    private final ExceptionHandlingAdvice advice = new ExceptionHandlingAdvice();

    @Test
    void handleCryptographicOperationException_returns400WithErrorCode702() {
        CryptographicOperationException ex = new CryptographicOperationException("signing failed");

        ResponseEntity<Object> response = advice.handleCryptographicOperationException(ex);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        ApiErrorResponseDto body = (ApiErrorResponseDto) response.getBody();
        assertNotNull(body);
        assertEquals(702, body.getCode());
        assertEquals("Cryptographic operation problem", body.getMessage());
        assertFalse(body.getErrors().isEmpty());
        assertEquals("signing failed", body.getErrors().get(0).getError());
    }
}
