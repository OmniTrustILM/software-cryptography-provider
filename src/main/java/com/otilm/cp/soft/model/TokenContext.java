package com.otilm.cp.soft.model;

import com.otilm.cp.soft.dao.entity.TokenInstance;

/**
 * A token the V2 interfaces addressed by attributes, together with the code that opens its keystore.
 *
 * <p>
 * The code travels with the context because the V2 interfaces have no activation step: it arrives with every request
 * rather than being held between them, so nothing needs to keep it to serve the next one.
 * </p>
 *
 * @param instance the token the request addressed
 * @param code the code that opens the token's keystore
 */
public record TokenContext(TokenInstance instance, String code) {
}
