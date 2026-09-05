package com.otilm.cp.soft.exception;

/** An attribute definition this connector does not publish. */
public class AttributeDefinitionMissingException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public AttributeDefinitionMissingException(String message) {
        super(message);
    }
}
