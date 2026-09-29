package com.otilm.cp.soft.util;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.cp.soft.collection.MLDSASecurityCategory;
import com.otilm.cp.soft.collection.SLHDSASecurityCategory;
import com.otilm.cp.soft.collection.SLHDSASignatureMode;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * The platform signature algorithms this connector signs with. V2 names every signature by one of them, so a key whose
 * parameter set none of them names cannot sign through V2.
 */
public final class SignatureAlgorithms {

    private static final Map<KeyAlgorithm, List<SignatureAlgorithm>> OFFERED = new EnumMap<>(Map
            .of(KeyAlgorithm.RSA,
                    List
                            .of(SignatureAlgorithm.SHA256_WITH_RSA, SignatureAlgorithm.SHA384_WITH_RSA,
                                    SignatureAlgorithm.SHA512_WITH_RSA, SignatureAlgorithm.SHA256_WITH_RSA_PSS,
                                    SignatureAlgorithm.SHA384_WITH_RSA_PSS, SignatureAlgorithm.SHA512_WITH_RSA_PSS),
                    KeyAlgorithm.ECDSA,
                    List
                            .of(SignatureAlgorithm.SHA256_WITH_ECDSA, SignatureAlgorithm.SHA384_WITH_ECDSA,
                                    SignatureAlgorithm.SHA512_WITH_ECDSA),
                    KeyAlgorithm.FALCON, List.of(SignatureAlgorithm.FALCON_1024), KeyAlgorithm.MLDSA,
                    List.of(SignatureAlgorithm.ML_DSA_44, SignatureAlgorithm.ML_DSA_65, SignatureAlgorithm.ML_DSA_87),
                    KeyAlgorithm.SLHDSA,
                    List
                            .of(SignatureAlgorithm.SLH_DSA_SHA2_128S, SignatureAlgorithm.SLH_DSA_SHA2_128F,
                                    SignatureAlgorithm.SLH_DSA_SHA2_192S, SignatureAlgorithm.SLH_DSA_SHA2_192F,
                                    SignatureAlgorithm.SLH_DSA_SHA2_256S, SignatureAlgorithm.SLH_DSA_SHA2_256F)));

    private SignatureAlgorithms() {
    }

    /**
     * The algorithms a key of the given algorithm can be offered, in the order a key offers them.
     *
     * @param algorithm the key's algorithm
     * @return the algorithms, empty for a key that does not sign
     */
    public static List<SignatureAlgorithm> offeredFor(KeyAlgorithm algorithm) {
        return OFFERED.getOrDefault(algorithm, List.of());
    }

    /** Every algorithm a key of this connector can be offered. */
    public static List<SignatureAlgorithm> offered() {
        return OFFERED.values().stream().flatMap(List::stream).toList();
    }

    /**
     * The algorithm a post-quantum key signs with, read from the parameter set its private-key row records. A pre-hash
     * key signs a digest rather than the message, which no platform algorithm names.
     *
     * @param algorithm the key's algorithm
     * @param parameters the parameter set the row records
     * @return the algorithm, empty where the platform names none for this parameter set
     * @throws IllegalArgumentException when the parameters describe no parameter set of the algorithm
     */
    public static Optional<SignatureAlgorithm> ofPostQuantumKey(KeyAlgorithm algorithm,
            Map<String, String> parameters) {
        if (algorithm != KeyAlgorithm.FALCON && signsADigest(parameters)) {
            return Optional.empty();
        }
        String code = switch (algorithm) {
            case FALCON -> "FALCON-" + parameters.get("degree");
            case MLDSA ->
                "ML-DSA-" + MLDSASecurityCategory.valueOf(Integer.parseInt(parameters.get("level"))).getParameterSet();
            case SLHDSA -> "SLH-DSA-" + parameters.get("hash") + "-"
                    + slhDsaCategory(parameters.get("securityCategory")).getSecurityParameterLength()
                    + SLHDSASignatureMode
                            .valueOf(parameters.get("tradeoff"))
                            .getParameterName()
                            .toUpperCase(Locale.ROOT);
            default -> throw new IllegalArgumentException("Not a post-quantum signature key: " + algorithm);
        };
        return SignatureAlgorithm.lookupByCode(code).filter(offeredFor(algorithm)::contains);
    }

    private static boolean signsADigest(Map<String, String> parameters) {
        String prehash = parameters.get("prehash");
        if (!"true".equals(prehash) && !"false".equals(prehash)) {
            throw new IllegalArgumentException("The parameter set states no pre-hash selection");
        }
        return Boolean.parseBoolean(prehash);
    }

    private static SLHDSASecurityCategory slhDsaCategory(String nistSecurityCategory) {
        return Stream
                .of(SLHDSASecurityCategory.values())
                .filter(category -> category.getNistSecurityCategory().equals(nistSecurityCategory))
                .findFirst()
                .orElseThrow(
                        () -> new IllegalArgumentException("No SLH-DSA security category " + nistSecurityCategory));
    }
}
