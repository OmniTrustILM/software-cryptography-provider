package com.otilm.cp.soft.model;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.sql.Timestamp;
import java.util.Map;

/**
 * Immutable snapshot of the key material extracted from a PKCS12 keystore, and the code that opened it.
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
 *
 * <p>
 * The code is kept beside the material because deriving it from what is stored costs as much as opening the keystore
 * did, and a request on the V2 interfaces carries the code and has to be held to it every time. It is no more exposed
 * here than the private keys beside it, which this record already holds in the clear.
 * </p>
 *
 * <p>
 * The version of the row this came out of is kept with it because nothing else can say whether it is still what the row
 * holds. A connector serving requests from more than one process shares only the database: what one of them discards,
 * the others never hear about, so a copy that is behind the row has to be recognised rather than waited out.
 * </p>
 *
 * @param privateKeys the private keys, indexed by alias
 * @param publicKeys the public keys, indexed by alias
 * @param openedWith the code that opens the token this material came out of
 * @param builtFrom the version of the token's row this was taken out of
 */
public record CachedKeyMaterial(Map<String, PrivateKey> privateKeys, Map<String, PublicKey> publicKeys,
        String openedWith, Timestamp builtFrom) {

    /**
     * What this may say about itself, which is the aliases it holds and never the code. A value reaches a log line
     * through nothing more than being printed, and the redaction a line passes through takes a secret out by the name
     * it was written under — a name a record prints its own components by is not one of them.
     */
    @Override
    public String toString() {
        return "CachedKeyMaterial[privateKeys=" + privateKeys.keySet() + ", publicKeys=" + publicKeys.keySet() + "]";
    }
}
