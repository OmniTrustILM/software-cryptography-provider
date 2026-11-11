package com.otilm.cp.soft.model;

/**
 * A key used by a cryptographic operation, with the key material.
 *
 * @param key the key the request addressed
 * @param material the keys its token holds
 */
public record OperationKey(CachedKeyData key, CachedKeyMaterial material) {
}
