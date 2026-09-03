package com.otilm.cp.soft.exception;

/**
 * Raised when a request addresses something this connector does not hold.
 *
 * <p>
 * The V2 interfaces declare no checked exceptions, so what the older services report as a checked absence is presented
 * here as the answer the contract names for it.
 * </p>
 */
public class ResourceMissingException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public ResourceMissingException(String message) {
        super(message);
    }

    public ResourceMissingException(String message, Throwable cause) {
        super(message, cause);
    }
}
