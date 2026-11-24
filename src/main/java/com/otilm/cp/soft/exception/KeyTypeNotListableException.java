package com.otilm.cp.soft.exception;

/** Raised when a listing or resolution asks for secret keys, which a software token never holds. */
public class KeyTypeNotListableException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public KeyTypeNotListableException(String message) {
        super(message);
    }
}
