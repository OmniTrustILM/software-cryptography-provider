package com.otilm.cp.soft.model;

import java.util.UUID;

/**
 * An open token with key material.
 *
 * @param uuid the token
 * @param material the keys the token holds
 */
public record OpenedToken(UUID uuid, CachedKeyMaterial material) {
}
