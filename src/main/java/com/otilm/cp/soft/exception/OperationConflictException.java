package com.otilm.cp.soft.exception;

/**
 * Raised when an operation identifier is reused for a request that is not the one it first identified.
 *
 * <p>
 * Answering with the first result would silently ignore what the second request asked for, so the contract has the
 * connector refuse it as a conflict.
 * </p>
 */
public class OperationConflictException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public OperationConflictException(String message) {
        super(message);
    }
}
