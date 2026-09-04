package com.otilm.cp.soft.api.v2;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.api.model.common.error.ProblemDetailExtended;
import com.otilm.cp.soft.api.CorrelationFilter;
import com.otilm.cp.soft.exception.ConcurrentRequestException;
import com.otilm.cp.soft.exception.CryptographicOperationException;
import com.otilm.cp.soft.exception.ExportableNotSupportedException;
import com.otilm.cp.soft.exception.KeyManagementException;
import com.otilm.cp.soft.exception.KeyMaterialMismatchException;
import com.otilm.cp.soft.exception.KeyNotExportableException;
import com.otilm.cp.soft.exception.KeyTypeNotExportableException;
import com.otilm.cp.soft.exception.KeyTypeNotImportableException;
import com.otilm.cp.soft.exception.MetricsUnavailableException;
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
import org.springframework.dao.OptimisticLockingFailureException;
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

    /**
     * Two requests writing the same thing at once. Either the database refused the second row, or the token both were
     * changing moved underneath one of them: a key is written into the token's keystore, so two requests adding a key
     * to one token contend on the token itself. Neither is a fault in the request, and repeating it reaches the state
     * the other one left.
     */
    @ExceptionHandler({ConcurrentRequestException.class, OptimisticLockingFailureException.class})
    public ResponseEntity<ProblemDetailExtended> handleConcurrentRequest(Exception e) {
        return problem(ErrorCode.SERVICE_UNAVAILABLE, "Another request is changing the same object. Retry.", e);
    }

    /**
     * The readings a scrape asked for could not be produced. The collector reads them again on its own schedule, so
     * this says only that this moment yielded nothing.
     */
    @ExceptionHandler(MetricsUnavailableException.class)
    public ResponseEntity<ProblemDetailExtended> handleMetricsUnavailable(MetricsUnavailableException e) {
        return problem(ErrorCode.SERVICE_UNAVAILABLE, "The metrics of this connector could not be produced.", e);
    }

    @ExceptionHandler(OperationNotTrackedException.class)
    public ResponseEntity<ProblemDetailExtended> handleNotTracked(OperationNotTrackedException e) {
        return problem(ErrorCode.OPERATION_NOT_TRACKED, "This connector tracks no asynchronous operation.", e);
    }

    /** The material holds a key type or algorithm this connector does not take in, which the contract names. */
    @ExceptionHandler(KeyTypeNotImportableException.class)
    public ResponseEntity<ProblemDetailExtended> handleKeyTypeNotImportable(KeyTypeNotImportableException e) {
        return problem(ErrorCode.KEY_TYPE_NOT_IMPORTABLE,
                "This connector does not take in a key of that type or algorithm.", e);
    }

    /** A key that stays exportable, which this connector cannot hold while it does not offer export. */
    @ExceptionHandler(ExportableNotSupportedException.class)
    public ResponseEntity<ProblemDetailExtended> handleExportableNotSupported(ExportableNotSupportedException e) {
        return problem(ErrorCode.EXPORTABLE_NOT_SUPPORTED, "This connector cannot hold a key that stays exportable.",
                e);
    }

    /** The algorithm is one this connector does not let out of a token. */
    @ExceptionHandler(KeyTypeNotExportableException.class)
    public ResponseEntity<ProblemDetailExtended> handleKeyTypeNotExportable(KeyTypeNotExportableException e) {
        return problem(ErrorCode.KEY_TYPE_NOT_EXPORTABLE,
                "This connector does not let a key of that type or algorithm out.", e);
    }

    /** The key was not made exportable, and the permission is never raised afterwards. */
    @ExceptionHandler(KeyNotExportableException.class)
    public ResponseEntity<ProblemDetailExtended> handleKeyNotExportable(KeyNotExportableException e) {
        return problem(ErrorCode.KEY_NOT_EXPORTABLE, "The key was not made exportable and cannot leave the token.", e);
    }

    /** The key the request addresses is not the key it describes. */
    @ExceptionHandler(KeyMaterialMismatchException.class)
    public ResponseEntity<ProblemDetailExtended> handleKeyMaterialMismatch(KeyMaterialMismatchException e) {
        return problem(ErrorCode.KEY_MATERIAL_MISMATCH, "The addressed key is not the key the request describes.", e);
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
