package com.otilm.cp.soft.model;

import com.otilm.cp.soft.dao.entity.KeyData;

/**
 * A key a V2 request addressed through its metadata, in the token that holds it.
 *
 * @param token the token the key lives in
 * @param key the key the request addressed
 */
public record KeyContext(TokenContext token, KeyData key) {
}
