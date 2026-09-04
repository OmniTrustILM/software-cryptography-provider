package com.otilm.cp.soft.exception;

/**
 * Raised when a key was not made exportable and so may never leave its token.
 */
public class KeyNotExportableException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public KeyNotExportableException(String message) {
        super(message);
    }
}
