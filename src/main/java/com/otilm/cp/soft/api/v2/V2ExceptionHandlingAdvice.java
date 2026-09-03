package com.otilm.cp.soft.api.v2;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.api.model.common.error.ProblemDetailExtended;
import com.otilm.cp.soft.api.CorrelationFilter;
import com.otilm.cp.soft.exception.ConcurrentRequestException;
import com.otilm.cp.soft.exception.CryptographicOperationException;
import com.otilm.cp.soft.exception.KeyManagementException;
import com.otilm.cp.soft.exception.NotSupportedException;
import com.otilm.cp.soft.exception.OperationConflictException;
import com.otilm.cp.soft.exception.OperationNotTrackedException;
import com.otilm.cp.soft.exception.ResourceMissingException;
import com.otilm.cp.soft.exception.TokenInstanceException;
import jakarta.validation.ConstraintViolationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Answers failures on the V2 interfaces as RFC 9457 problem documents.
 *
 * <p>
 * The document's {@code errorCode} is what a caller branches on, so each failure maps to the code the contract names
 * for it. The detail is this connector's own wording rather than the exception message: a message from the key
 * technology can quote a key, an alias or a passphrase, and a problem document is forwarded to the platform and logged
 * there. The message still reaches this connector's own log.
 * </p>
 *
 * <p>
 * Scoped to the V2 controllers, since the V1 surface answers with its own error shape and must keep doing so. It takes
 * precedence over the connector-wide advice for those controllers. The handler of last resort keeps that boundary
 * closed: without it an unforeseen failure would reach the connector-wide advice and answer a V2 caller in the V1
 * shape.
 * </p>
 *
 * <p>
 * Every document carries the trace the caller sent, so a failure answered here can be matched to the request that
 * caused it in the platform's own log. The occurrence and the content type are left to the framework, which sets the
 * request path and {@code application/problem+json} on any problem document a handler returns.
 * </p>
 */
@Order(Ordered.HIGHEST_PRECEDENCE)
@RestControllerAdvice(basePackages = "com.otilm.cp.soft.api.v2")
public class V2ExceptionHandlingAdvice {

    private static final Logger logger = LoggerFactory.getLogger(V2ExceptionHandlingAdvice.class);

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ProblemDetailExtended> handleUnreadableBody(HttpMessageNotReadableException e) {
        return problem(ErrorCode.BAD_REQUEST, "The request body could not be read.", e);
    }

    @ExceptionHandler({MethodArgumentNotValidException.class, ConstraintViolationException.class})
    public ResponseEntity<ProblemDetailExtended> handleValidationFailure(Exception e) {
        return problem(ErrorCode.VALIDATION_FAILED, "The request body breaks a field rule.", e);
    }

    @ExceptionHandler(ValidationException.class)
    public ResponseEntity<ProblemDetailExtended> handleAttributeValidationFailure(ValidationException e) {
        return problem(ErrorCode.VALIDATION_FAILED, "The supplied attributes break a value rule.", e);
    }

    @ExceptionHandler(ResourceMissingException.class)
    public ResponseEntity<ProblemDetailExtended> handleNotFound(ResourceMissingException e) {
        return problem(ErrorCode.RESOURCE_NOT_FOUND, "The requested object does not exist.", e);
    }

    @ExceptionHandler(OperationConflictException.class)
    public ResponseEntity<ProblemDetailExtended> handleAlreadyExists(OperationConflictException e) {
        return problem(ErrorCode.RESOURCE_ALREADY_EXISTS,
                "The operation identifier was reused for a request that is not the same one.", e);
    }

    @ExceptionHandler(ConcurrentRequestException.class)
    public ResponseEntity<ProblemDetailExtended> handleConcurrentRequest(ConcurrentRequestException e) {
        return problem(ErrorCode.SERVICE_UNAVAILABLE, "Another request is creating the same object. Retry.", e);
    }

    @ExceptionHandler(OperationNotTrackedException.class)
    public ResponseEntity<ProblemDetailExtended> handleNotTracked(OperationNotTrackedException e) {
        return problem(ErrorCode.OPERATION_NOT_TRACKED, "This connector tracks no asynchronous operation.", e);
    }

    @ExceptionHandler(NotSupportedException.class)
    public ResponseEntity<ProblemDetailExtended> handleNotSupported(NotSupportedException e) {
        return problem(ErrorCode.OPERATION_NOT_SUPPORTED, "This connector does not offer the requested operation.", e);
    }

    @ExceptionHandler({KeyManagementException.class, TokenInstanceException.class})
    public ResponseEntity<ProblemDetailExtended> handleKeyManagement(Exception e) {
        return problem(ErrorCode.ATTRIBUTES_ERROR, "The supplied token or key context could not be used.", e);
    }

    @ExceptionHandler(CryptographicOperationException.class)
    public ResponseEntity<ProblemDetailExtended> handleCryptographicOperation(CryptographicOperationException e) {
        return problem(ErrorCode.BAD_REQUEST, "The cryptographic operation could not be performed.", e);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetailExtended> handleUnexpectedFailure(Exception e) {
        if (logger.isErrorEnabled()) {
            logger.error("A v2 request known as {} failed with {}", correlationId(), classOf(e));
        }
        return problem(ErrorCode.INTERNAL_SERVER_ERROR, "The request could not be completed.", e);
    }

    private static ResponseEntity<ProblemDetailExtended> problem(ErrorCode errorCode, String detail, Exception cause) {
        if (logger.isDebugEnabled()) {
            logger
                    .debug("Answering the v2 request known as {} with {} after {}", correlationId(), errorCode,
                            classOf(cause));
        }
        ProblemDetailExtended problem = ProblemDetailExtended.fromErrorCode(errorCode, detail, null, correlationId());
        return ResponseEntity.status(errorCode.getStatus()).body(problem);
    }

    /**
     * The identifier this request is known by, which the platform matches this document to its own record of the
     * request with. Every request has one: the caller states it, or it was given one when it arrived.
     */
    private static String correlationId() {
        return MDC.get(CorrelationFilter.CORRELATION_ID);
    }

    /**
     * What kind of failure occurred, which is as much as can be written down. A message from the key technology can
     * quote a key, an alias or a passphrase, and neither the response nor this connector's log may carry one. The
     * identifier beside it is what leads back to the request, since the failure itself is not recorded.
     */
    private static String classOf(Exception cause) {
        return cause == null ? "no failure" : cause.getClass().getName();
    }
}
