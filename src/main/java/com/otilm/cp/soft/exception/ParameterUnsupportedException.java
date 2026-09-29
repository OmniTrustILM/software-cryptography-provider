package com.otilm.cp.soft.exception;

/**
 * Raised when a request asks for something this connector cannot perform: a parameter value it does not offer, or a
 * signature the key cannot make, either because the selection does not fit the key or because no platform signature
 * algorithm names the key's parameter set.
 */
public class ParameterUnsupportedException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public ParameterUnsupportedException(String message) {
        super(message);
    }
}
