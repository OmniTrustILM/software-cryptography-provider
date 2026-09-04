package com.otilm.cp.soft.exception;

/**
 * Raised when the key's algorithm is one this connector does not let out of a token.
 */
public class KeyTypeNotExportableException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public KeyTypeNotExportableException(String message) {
        super(message);
    }
}
