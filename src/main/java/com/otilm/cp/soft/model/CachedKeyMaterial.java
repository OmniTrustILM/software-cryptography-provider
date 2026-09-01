package com.otilm.cp.soft.model;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;

/**
 * Immutable snapshot of the key material extracted from a PKCS12 keystore.
 *
 * <p>
 * Both maps are unmodifiable and populated once at cache-load time. Instances of this record are safe for concurrent
 * reads with no synchronization because:
 * </p>
 * <ul>
 * <li>The {@link PrivateKey} implementations used here ({@code BCRSAPrivateCrtKey}, {@code BCECPrivateKey},
 * {@code BCFalconPrivateKey}, {@code BCMLDSAPrivateKey}, {@code BCSLHDSAPrivateKey}) store all key material in
 * {@code byte[]} fields set at construction time. No mutable state accumulates on subsequent method calls.</li>
 * <li>{@link PublicKey} implementations are immutable by the same verification.</li>
 * <li>Both maps are wrapped in {@code Collections.unmodifiableMap()} and are never replaced or modified after
 * construction.</li>
 * </ul>
 *
 * <p>
 * Keys are indexed by alias, which equals {@code KeyData.name} for every entry in this connector.
 * </p>
 *
 * <p>
 * The underlying {@code KeyStore} is used only during construction and is immediately discarded.
 * </p>
 */
public record CachedKeyMaterial(Map<String, PrivateKey> privateKeys, Map<String, PublicKey> publicKeys) {
}
