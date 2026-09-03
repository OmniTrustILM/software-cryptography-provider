package com.otilm.cp.soft.model;

/**
 * Whether the token a request addressed can be used.
 */
public enum TokenAvailability {

    /** The token exists and the code the context carries opens it. */
    AVAILABLE,

    /** No token answers to the context. A context asking for a new one creates it when it is next used. */
    MISSING,

    /** The token was addressed but cannot be used, most often because the code does not open it. */
    UNUSABLE
}
