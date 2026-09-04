package com.otilm.cp.soft.exception;

/**
 * Raised when the key material holds a key type or algorithm this connector does not accept as an import.
 *
 * <p>
 * The contract has the connector check the type it advertises before it opens anything, so a mismatch is refused
 * without the material ever being decrypted.
 * </p>
 */
public class KeyTypeNotImportableException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public KeyTypeNotImportableException(String message) {
        super(message);
    }
}
