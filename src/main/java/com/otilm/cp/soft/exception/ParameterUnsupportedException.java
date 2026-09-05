package com.otilm.cp.soft.exception;

/**
 * Raised when a request states a combination of parameters this connector cannot perform.
 *
 * <p>
 * Each parameter is published as a choice of its own, so a schema of independent choices cannot say that one of them
 * rules out a value of another. A caller can therefore always assemble a combination no algorithm implements, and this
 * is what says so.
 * </p>
 */
public class ParameterUnsupportedException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public ParameterUnsupportedException(String message) {
        super(message);
    }
}
