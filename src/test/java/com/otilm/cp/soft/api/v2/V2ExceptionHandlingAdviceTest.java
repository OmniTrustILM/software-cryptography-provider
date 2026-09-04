package com.otilm.cp.soft.api.v2;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.api.model.common.error.ProblemDetailExtended;
import com.otilm.cp.soft.exception.ConcurrentRequestException;
import com.otilm.cp.soft.exception.CryptographicOperationException;
import com.otilm.cp.soft.exception.KeyManagementException;
import com.otilm.cp.soft.exception.MetricsUnavailableException;
import com.otilm.cp.soft.exception.NotSupportedException;
import com.otilm.cp.soft.exception.ResourceMissingException;
import jakarta.validation.ConstraintViolationException;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The V2 interfaces answer failures as RFC 9457 problem documents carrying an {@code errorCode}, which is what a caller
 * matches on. The V1 surface keeps its own error shape, so this advice is scoped to the V2 controllers.
 */
class V2ExceptionHandlingAdviceTest {

    private final V2ExceptionHandlingAdvice advice = new V2ExceptionHandlingAdvice();

    @Test
    void anUnreadableBodyIsABadRequest() {
        // given
        HttpMessageNotReadableException failure = new HttpMessageNotReadableException("unexpected end of input", null,
                null);

        // when
        ResponseEntity<ProblemDetailExtended> response = advice.handleUnreadableBody(failure);

        // then
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorCode.BAD_REQUEST, body(response).getErrorCode());
    }

    @Test
    void aBrokenFieldRuleIsUnprocessable() {
        // given
        // when
        ResponseEntity<ProblemDetailExtended> response = advice
                .handleValidationFailure(new ConstraintViolationException("keyMeta is required", Set.of()));

        // then
        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, response.getStatusCode());
        assertEquals(ErrorCode.VALIDATION_FAILED, body(response).getErrorCode());
    }

    /**
     * Attribute values are checked by the code both interface generations share, which reports a broken value rule as a
     * validation failure of its own kind. The V2 surface must answer it in the V2 shape.
     */
    @Test
    void aBrokenAttributeValueRuleIsUnprocessable() {
        // given
        // when
        ResponseEntity<ProblemDetailExtended> response = advice
                .handleAttributeValidationFailure(new ValidationException("the token code is required"));

        // then
        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, response.getStatusCode());
        assertEquals(ErrorCode.VALIDATION_FAILED, body(response).getErrorCode());
    }

    /**
     * Whatever else fails must still be answered in the V2 shape. Without this the connector-wide advice would answer a
     * V2 caller in the V1 error shape, which carries no {@code errorCode} and echoes the failure message.
     */
    @Test
    void anUnforeseenFailureIsAnInternalError() {
        // given
        String secret = "correct horse battery staple";

        // when
        ResponseEntity<ProblemDetailExtended> response = advice
                .handleUnexpectedFailure(new IllegalStateException("cannot open the keystore with " + secret));

        // then
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        ProblemDetailExtended problem = body(response);
        assertEquals(ErrorCode.INTERNAL_SERVER_ERROR, problem.getErrorCode());
        assertFalse(String.valueOf(problem.getDetail()).contains(secret),
                () -> "the failure message leaked into " + problem.getDetail());
    }

    /** A token moving underneath a request is the same kind of race, and is answered the same way. */
    @Test
    void aContendedTokenIsRetryable() {
        // given
        // when
        ResponseEntity<ProblemDetailExtended> response = advice
                .handleConcurrentRequest(new OptimisticLockingFailureException("the token moved"));

        // then
        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, response.getStatusCode());
        assertTrue(body(response).isRetryable());
    }

    /**
     * Losing a race to another request writing the same row is not a fault in the request, and repeating it reaches the
     * row that request wrote, so it is answered as retryable rather than as a conflict.
     */
    @Test
    void losingARaceIsRetryable() {
        // given
        // when
        ResponseEntity<ProblemDetailExtended> response = advice
                .handleConcurrentRequest(new ConcurrentRequestException("token v2-a is being created", null));

        // then
        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, response.getStatusCode());
        assertEquals(ErrorCode.SERVICE_UNAVAILABLE, body(response).getErrorCode());
        assertTrue(body(response).isRetryable(), "a caller that repeats the request gets the object");
    }

    /**
     * A collector reads the metrics again on its own schedule, so a reading that could not be taken says only that this
     * moment yielded nothing.
     */
    @Test
    void metricsThatCouldNotBeProducedAreRetryable() {
        // given
        // when
        ResponseEntity<ProblemDetailExtended> response = advice
                .handleMetricsUnavailable(new MetricsUnavailableException("the readings could not be written"));

        // then
        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, response.getStatusCode());
        assertEquals(ErrorCode.SERVICE_UNAVAILABLE, body(response).getErrorCode());
        assertTrue(body(response).isRetryable());
    }

    @Test
    void aMissingObjectIsNotFound() {
        // given
        // when
        ResponseEntity<ProblemDetailExtended> response = advice
                .handleNotFound(new ResourceMissingException("the key does not exist"));

        // then
        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertEquals(ErrorCode.RESOURCE_NOT_FOUND, body(response).getErrorCode());
    }

    /** Asynchronous execution is not offered, so a request for it is answered as unimplemented rather than refused. */
    @Test
    void anUnsupportedOperationIsNotImplemented() {
        // given
        // when
        ResponseEntity<ProblemDetailExtended> response = advice
                .handleNotSupported(new NotSupportedException("asynchronous execution is not supported"));

        // then
        assertEquals(HttpStatus.NOT_IMPLEMENTED, response.getStatusCode());
        assertEquals(ErrorCode.OPERATION_NOT_SUPPORTED, body(response).getErrorCode());
    }

    @Test
    void aKeyManagementFailureIsAConnectorProblem() {
        // given
        // when
        ResponseEntity<ProblemDetailExtended> response = advice
                .handleKeyManagement(new KeyManagementException("cannot open the keystore"));

        // then
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorCode.ATTRIBUTES_ERROR, body(response).getErrorCode());
    }

    @Test
    void aCryptographicOperationFailureIsAConnectorProblem() {
        // given
        // when
        ResponseEntity<ProblemDetailExtended> response = advice
                .handleCryptographicOperation(new CryptographicOperationException("signing failed"));

        // then
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorCode.BAD_REQUEST, body(response).getErrorCode());
    }

    /**
     * A problem document states the code, the status it was answered with and whether retrying can help, and carries a
     * timestamp. Everything a caller branches on must be present.
     */
    @Test
    void everyProblemStatesItsCodeStatusAndTime() {
        // given
        List<ResponseEntity<ProblemDetailExtended>> answers = List
                .of(advice.handleNotFound(new ResourceMissingException("the key does not exist")),
                        advice.handleNotSupported(new NotSupportedException("no")),
                        advice.handleKeyManagement(new KeyManagementException("no")));

        // when
        // then
        for (ResponseEntity<ProblemDetailExtended> answer : answers) {
            ProblemDetailExtended problem = body(answer);
            assertNotNull(problem.getErrorCode());
            assertNotNull(problem.getTimestamp());
            assertNotNull(problem.getType());
            assertEquals(answer.getStatusCode().value(), problem.getStatus());
            assertEquals(problem.getErrorCode().isRetryable(), problem.isRetryable());
        }
    }

    /** A message from the technology can name a key or a passphrase, so the detail is the connector's own wording. */
    @Test
    void theDetailDoesNotEchoTheFailureMessage() {
        // given
        String secret = "correct horse battery staple";

        // when
        ProblemDetailExtended problem = body(
                advice.handleCryptographicOperation(new CryptographicOperationException("cannot decrypt " + secret)));

        // then
        assertFalse(String.valueOf(problem.getDetail()).contains(secret),
                () -> "the failure message leaked into " + problem.getDetail());
        assertTrue(problem.getDetail() != null && !problem.getDetail().isBlank(), "a problem must explain itself");
    }

    /**
     * A message from the key technology can quote a key, an alias or a passphrase, and neither the response nor this
     * connector's log may carry one. What is written down is the kind of failure and the identifier leading back to the
     * request, which is what an operator acts on.
     */
    @Test
    void recordsTheKindOfFailureAndNothingOfTheFailureItself() {
        // given
        String secret = "correct horse battery staple";
        Logger logger = (Logger) LoggerFactory.getLogger(V2ExceptionHandlingAdvice.class);
        ListAppender<ILoggingEvent> recorded = new ListAppender<>();
        recorded.start();
        logger.addAppender(recorded);
        Level was = logger.getLevel();
        logger.setLevel(Level.DEBUG);

        // when
        try {
            advice.handleUnexpectedFailure(new IllegalStateException("cannot open the keystore with " + secret));
        } finally {
            logger.detachAppender(recorded);
            logger.setLevel(was);
        }

        // then
        assertFalse(recorded.list.isEmpty(), "a failure must leave something to act on");
        for (ILoggingEvent event : recorded.list) {
            assertNull(event.getThrowableProxy(), "the failure itself must not be written down");
            assertFalse(event.getFormattedMessage().contains(secret),
                    () -> "the failure message leaked into the log: " + event.getFormattedMessage());
        }
        assertTrue(
                recorded.list
                        .stream()
                        .anyMatch(event -> event.getFormattedMessage().contains(IllegalStateException.class.getName())),
                "the kind of failure has to be recorded");
    }

    private static ProblemDetailExtended body(ResponseEntity<ProblemDetailExtended> response) {
        ProblemDetailExtended problem = response.getBody();
        assertNotNull(problem, "a problem document is required");
        return problem;
    }
}
