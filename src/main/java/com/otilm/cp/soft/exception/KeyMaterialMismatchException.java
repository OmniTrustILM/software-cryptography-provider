package com.otilm.cp.soft.exception;

/**
 * Raised when the key a request addresses is not the key it describes.
 */
public class KeyMaterialMismatchException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public KeyMaterialMismatchException(String message) {
        super(message);
    }
}
