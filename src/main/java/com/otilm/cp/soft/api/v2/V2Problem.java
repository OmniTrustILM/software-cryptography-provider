package com.otilm.cp.soft.api.v2;

import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.api.model.common.error.ProblemDetailExtended;
import com.otilm.cp.soft.api.CorrelationFilter;
import org.slf4j.MDC;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;

/**
 * Builds the problem document the V2 interfaces answer a failure with.
 *
 * <p>
 * Every V2 failure is answered the same way wherever it was raised, so the document is built in one place: a caller
 * branches on the {@code errorCode}, and a document assembled twice would eventually differ in what it carries.
 * </p>
 */
final class V2Problem {

    private V2Problem() {
    }

    /** The document for a failure, answered with the status the error code states. */
    static ResponseEntity<ProblemDetailExtended> answer(ErrorCode errorCode, String detail) {
        return answer(errorCode, detail, errorCode.getStatus());
    }

    /**
     * The document for a failure, answered with a status of its own.
     *
     * <p>
     * A request that never reached an operation fails for a reason HTTP states more precisely than the contract's error
     * codes do — a method or a media type the route does not serve. The status is what a caller, a client library and a
     * proxy all act on, so it is kept, and the error code beside it names the nearest kind of failure the contract
     * defines.
     * </p>
     */
    static ResponseEntity<ProblemDetailExtended> answer(ErrorCode errorCode, String detail, HttpStatusCode status) {
        return ResponseEntity.status(status).body(document(errorCode, detail, status));
    }

    /** The document itself, for an answer that has something of its own to say alongside it. */
    static ProblemDetailExtended document(ErrorCode errorCode, String detail, HttpStatusCode status) {
        ProblemDetailExtended problem = ProblemDetailExtended.fromErrorCode(errorCode, detail, null, correlationId());
        problem.setStatus(status.value());
        return problem;
    }

    /**
     * The identifier this request is known by, which the platform matches this document to its own record of the
     * request with. Every request has one: the caller states it, or it was given one when it arrived.
     */
    static String correlationId() {
        return MDC.get(CorrelationFilter.CORRELATION_ID);
    }
}
