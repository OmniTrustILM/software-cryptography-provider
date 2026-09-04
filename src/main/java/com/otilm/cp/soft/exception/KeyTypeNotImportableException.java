package com.otilm.cp.soft.exception;

/**
 * Raised when the key material holds a key type or algorithm this connector does not accept as an import.
 *
 * <p>
 * The kind of key a request states is checked before anything is opened, as the contract has it. The algorithm is not
 * stated anywhere: it lives inside the protected material, so an algorithm this connector does not hold is only known
 * once the material has been opened.
 * </p>
 */
public class KeyTypeNotImportableException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public KeyTypeNotImportableException(String message) {
        super(message);
    }
}
