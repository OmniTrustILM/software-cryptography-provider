package com.otilm.cp.soft.exception;

/**
 * Raised when a request asks after an asynchronous operation.
 *
 * <p>
 * This provider completes every operation inline and accepts none for asynchronous processing, so it never has an
 * operation to track and answers as the contract states for one it no longer tracks.
 * </p>
 */
public class OperationNotTrackedException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public OperationNotTrackedException(String message) {
        super(message);
    }
}
