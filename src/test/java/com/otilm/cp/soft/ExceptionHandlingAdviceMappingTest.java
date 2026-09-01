package com.otilm.cp.soft;

import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.NotDeletableException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.cp.soft.dto.ApiErrorResponseDto;
import com.otilm.cp.soft.exception.CryptographicOperationException;
import com.otilm.cp.soft.exception.NotSupportedException;
import com.otilm.cp.soft.exception.TokenInstanceException;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.BeanInstantiationException;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The mapping from exception to HTTP status and error code. Clients switch on the code, so both halves are part of the
 * connector's contract and are pinned here.
 */
class ExceptionHandlingAdviceMappingTest {

    private final ExceptionHandlingAdvice advice = new ExceptionHandlingAdvice();

    private static ApiErrorResponseDto bodyOf(ResponseEntity<Object> response) {
        ApiErrorResponseDto body = assertInstanceOf(ApiErrorResponseDto.class, response.getBody());
        assertNotNull(body);
        assertTrue(body.getTimestamp() > 0, "every error carries a timestamp");
        return body;
    }

    private static Stream<Arguments> simpleMappings() {
        ExceptionHandlingAdvice advice = new ExceptionHandlingAdvice();
        return Stream
                .of(Arguments
                        .of("NotFoundException", HttpStatus.NOT_FOUND, 404, "Object not found",
                                (Function<Void, ResponseEntity<Object>>) v -> advice
                                        .handleNotFoundException(new NotFoundException("token", "abc"))),
                        Arguments
                                .of("AlreadyExistException", HttpStatus.BAD_REQUEST, 405, "Object already exists",
                                        (Function<Void, ResponseEntity<Object>>) v -> advice
                                                .handleAlreadyExistException(
                                                        new AlreadyExistException("token", "abc"))),
                        Arguments
                                .of("NotDeletableException", HttpStatus.BAD_REQUEST, 406, "Object cannot be deleted",
                                        (Function<Void, ResponseEntity<Object>>) v -> advice
                                                .handleNotDeletableException(
                                                        new NotDeletableException("token", "abc"))),
                        Arguments
                                .of("TokenInstanceException", HttpStatus.BAD_REQUEST, 701, "Token instance problem",
                                        (Function<Void, ResponseEntity<Object>>) v -> advice
                                                .handleTokenInstanceException(
                                                        new TokenInstanceException("token broken"))),
                        Arguments
                                .of("CryptographicOperationException", HttpStatus.BAD_REQUEST, 702,
                                        "Cryptographic operation problem",
                                        (Function<Void, ResponseEntity<Object>>) v -> advice
                                                .handleCryptographicOperationException(
                                                        new CryptographicOperationException("signing failed"))));
    }

    @ParameterizedTest(name = "{0} -> {1} / {2}")
    @MethodSource("simpleMappings")
    void exceptionMapsToItsStatusAndCode(String label, HttpStatus status, int code, String message,
            Function<Void, ResponseEntity<Object>> handler) {
        ResponseEntity<Object> response = handler.apply(null);

        assertEquals(status, response.getStatusCode(), label + " status changed");
        ApiErrorResponseDto body = bodyOf(response);
        assertEquals(code, body.getCode(), label + " error code changed");
        assertEquals(message, body.getMessage());
        assertFalse(body.getErrors().isEmpty(), label + " reported no error detail");
    }

    @Test
    void notSupportedIsReportedAsNotImplemented() {
        ResponseEntity<Object> response = advice
                .handleNotSupportedException(new NotSupportedException("symmetric keys are not supported"));

        assertEquals(HttpStatus.NOT_IMPLEMENTED, response.getStatusCode());
        ApiErrorResponseDto body = bodyOf(response);
        assertEquals(501, body.getCode());
        assertEquals("symmetric keys are not supported", body.getErrors().get(0).getError());
    }

    @Test
    void unexpectedExceptionsBecomeInternalServerError() {
        ResponseEntity<Object> response = advice.handleAll(new IllegalStateException("boom"));

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        ApiErrorResponseDto body = bodyOf(response);
        assertEquals(99, body.getCode());
        assertEquals("Unexpected exception occurred", body.getMessage());
        // The class name and message are reported, never a stack trace at INFO.
        assertEquals("Unexpected error", body.getErrors().get(0).getError());
        assertEquals("IllegalStateException", body.getErrors().get(0).getType());
    }

    @Test
    void validationErrorsAreReturnedAsDescriptions() {
        ValidationException ex = new ValidationException(
                List.of(ValidationError.create("first problem"), ValidationError.create("second problem")));

        List<String> errors = advice.handleValidationException(ex);

        assertEquals(2, errors.size());
        assertTrue(errors.get(0).contains("first problem"));
        assertTrue(errors.get(1).contains("second problem"));
    }

    @Test
    void bindingFailuresAreReportedPerField() throws NoSuchMethodException {
        BindingResult binding = new BeanPropertyBindingResult(new Object(), "request");
        binding.rejectValue(null, "code", "the object is wrong");
        binding.addError(new org.springframework.validation.FieldError("request", "name", "the name is wrong"));

        MethodParameter parameter = new MethodParameter(
                ExceptionHandlingAdviceMappingTest.class.getDeclaredMethod("sampleMethod", String.class), 0);
        MethodArgumentNotValidException ex = new MethodArgumentNotValidException(parameter, binding);

        ResponseEntity<Object> response = advice.handleMethodArgumentNotValidException(ex);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        ApiErrorResponseDto body = assertInstanceOf(ApiErrorResponseDto.class, response.getBody());
        assertEquals(80, body.getCode());
        // One field error and one global error are both reported.
        assertEquals(2, body.getErrors().size());
    }

    @SuppressWarnings("unused")
    private void sampleMethod(String argument) {
        // Only a source of a MethodParameter for the test above.
    }

    @Test
    void typeMismatchReportsTheOffendingValue() throws NoSuchMethodException {
        MethodParameter parameter = new MethodParameter(
                ExceptionHandlingAdviceMappingTest.class.getDeclaredMethod("sampleMethod", String.class), 0);
        MethodArgumentTypeMismatchException ex = new MethodArgumentTypeMismatchException("not-a-uuid",
                java.util.UUID.class, "uuid", parameter, new IllegalArgumentException("bad"));

        ResponseEntity<Object> response = advice.handleMethodArgumentTypeMismatchException(ex);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        ApiErrorResponseDto body = bodyOf(response);
        assertEquals(81, body.getCode());
        assertEquals("uuid", body.getErrors().get(0).getError());
        assertEquals("not-a-uuid", body.getErrors().get(0).getDetail());
    }

    @Test
    void unreadableBodyWithAnInvalidFormatNamesTheField() throws Exception {
        InvalidFormatException cause = InvalidFormatException
                .from(new com.fasterxml.jackson.core.JsonFactory().createParser("{}"), "not an integer", "abc",
                        Integer.class);
        cause.prependPath(new Object(), "keySize");

        HttpMessageNotReadableException ex = new HttpMessageNotReadableException("cannot read", cause);

        ResponseEntity<Object> response = advice.handleHttpMessageNotReadableException(ex);

        ApiErrorResponseDto body = bodyOf(response);
        assertEquals(81, body.getCode());
        // The offending field is named from the deserialization path rather than the raw message.
        assertEquals("keySize", body.getErrors().get(0).getError());
        assertEquals("abc", body.getErrors().get(0).getDetail());
    }

    @Test
    void unreadableBodyWithoutAnInvalidFormatFallsBackToTheRootCause() {
        HttpMessageNotReadableException ex = new HttpMessageNotReadableException("cannot read body",
                new BeanInstantiationException(Object.class, "root cause message"));

        ResponseEntity<Object> response = advice.handleHttpMessageNotReadableException(ex);

        ApiErrorResponseDto body = bodyOf(response);
        assertEquals(81, body.getCode());
        assertTrue(body.getErrors().get(0).getError().contains("root cause message"));
    }
}
