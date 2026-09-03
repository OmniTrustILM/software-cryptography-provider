package com.otilm.cp.soft.exception;

/**
 * Raised when another request wrote the row this one was about to write.
 *
 * <p>
 * The object this request addressed is being created by another request at the same moment. Retrying reaches the row
 * that request wrote, so this is reported as a retryable condition rather than a conflict: nothing about the request is
 * wrong, and the caller repeating it gets the answer it asked for.
 * </p>
 *
 * <p>
 * Recovering inside the failed request instead is not possible. The database reports the collision through the
 * persistence context, which the failed insert leaves unusable, so reading the winning row would flush the insert that
 * just failed and fail again.
 * </p>
 */
public class ConcurrentRequestException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public ConcurrentRequestException(String message, Throwable cause) {
        super(message, cause);
    }
}
