package com.otilm.cp.soft.exception;

/**
 * Raised when an import asks for a key that stays exportable and this connector cannot hold one.
 *
 * <p>
 * Whether a key may leave the token can never be changed afterwards, so accepting the request would promise something
 * the key could not deliver.
 * </p>
 */
public class ExportableNotSupportedException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public ExportableNotSupportedException(String message) {
        super(message);
    }
}
