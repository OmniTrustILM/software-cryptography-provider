package com.otilm.cp.soft.exception;

/** Protected key material this connector could not get a key out of. */
public class KeyDecryptionFailedException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public KeyDecryptionFailedException(String message) {
        super(message);
    }
}
