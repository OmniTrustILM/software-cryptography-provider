package com.otilm.cp.soft.model;

import com.otilm.cp.soft.dao.entity.TokenInstance;

/**
 * A token the V2 interfaces addressed by attributes, together with the code that opens its keystore.
 *
 * <p>
 * The code travels with the context because the V2 interfaces have no activation step: it arrives with every request
 * rather than being asked for once. The token keeps the code it was last opened with all the same, since the operations
 * this provider performs read it from there, and a token addressed only through these interfaces would otherwise have
 * none.
 * </p>
 *
 * @param instance the token the request addressed
 * @param code the code that opens the token's keystore
 */
public record TokenContext(TokenInstance instance, String code) {
}
