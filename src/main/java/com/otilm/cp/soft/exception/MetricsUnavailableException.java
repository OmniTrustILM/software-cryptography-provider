package com.otilm.cp.soft.exception;

/**
 * Raised when the metrics of this connector could not be produced.
 *
 * <p>
 * Readings are taken as a scrape is answered, so a reading that cannot be taken, or an exposition that cannot be
 * written, leaves nothing to answer with. Nothing about the request is wrong and the next scrape is likely to succeed,
 * so this is reported as a service that is momentarily unavailable.
 * </p>
 */
public class MetricsUnavailableException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public MetricsUnavailableException(String message) {
        super(message);
    }

    public MetricsUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
