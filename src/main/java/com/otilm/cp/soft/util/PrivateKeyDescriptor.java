package com.otilm.cp.soft.util;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.cryptography.key.value.CustomKeyValue;
import com.otilm.cp.soft.collection.EcdsaCurveName;
import com.otilm.cp.soft.collection.FalconDegree;
import com.otilm.cp.soft.collection.MLDSASecurityCategory;
import com.otilm.cp.soft.collection.MLKEMSecurityCategory;
import com.otilm.cp.soft.collection.SLHDSAHash;
import com.otilm.cp.soft.collection.SLHDSASecurityCategory;
import com.otilm.cp.soft.collection.SLHDSASignatureMode;
import com.otilm.cp.soft.exception.KeyTypeNotImportableException;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.util.HashMap;
import java.util.Locale;
import java.util.function.Predicate;
import java.util.stream.Stream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

/**
 * What a key row says about a private key this provider holds.
 *
 * <p>
 * A private key is never given out, so the row describes it instead of carrying it: which parameter set it belongs to
 * and, for the two algorithms that have both forms, whether it signs a message or a digest of one. That last one is
 * read when a signature is prepared, so a key whose row does not state it cannot be used.
 * </p>
 *
 * <p>
 * A generated key is described from the request that asked for it. A key that arrived as material has no such request,
 * so it is described from the key itself: the parameter set is what the key states its algorithm as. The two must
 * agree, or the same key would be described differently depending on how it came to be here.
 * </p>
 */
public final class PrivateKeyDescriptor {

    /** What a row says instead of the key, which is where the key is rather than what it is. */
    private static final String LOCATION = "managed by external token";

    /** The parameter sets of the two algorithms that sign a digest name themselves so. */
    private static final String PREHASH_MARKER = "-WITH-";

    private PrivateKeyDescriptor() {
    }

    /**
     * Describes a private key from the key itself.
     *
     * @param algorithm the algorithm the material held
     * @param keyPair the key pair read out of it
     * @return the description a key row carries
     */
    public static CustomKeyValue of(KeyAlgorithm algorithm, KeyPair keyPair) {
        String parameterSet = keyPair.getPrivate().getAlgorithm();
        HashMap<String, String> stated = new HashMap<>();
        switch (algorithm) {
            case RSA -> stated.put("location", LOCATION);
            case ECDSA -> {
                EcdsaCurveName curve = curveOf(keyPair);
                stated.put("curve.name", curve.name());
                stated.put("curve.description", curve.getDescription());
            }
            case FALCON -> stated.put("degree", Integer.toString(degreeOf(parameterSet).getDegree()));
            case MLDSA -> {
                stated.put("level", Integer.toString(mlDsaCategoryOf(parameterSet).getNistSecurityCategory()));
                stated.put("prehash", String.valueOf(signsADigest(parameterSet)));
            }
            case SLHDSA -> {
                stated.put("securityCategory", slhDsaCategoryOf(parameterSet).getNistSecurityCategory());
                stated.put("hash", slhDsaHashOf(parameterSet).getHashName());
                stated.put("tradeoff", slhDsaModeOf(parameterSet).name());
                stated.put("prehash", String.valueOf(signsADigest(parameterSet)));
            }
            case MLKEM ->
                stated.put("securityCategory", String.valueOf(mlKemCategoryOf(parameterSet).getNistSecurityCategory()));
            default -> throw unsupported("the algorithm " + algorithm.getCode());
        }
        CustomKeyValue described = new CustomKeyValue();
        described.setValues(stated);
        return described;
    }

    /** Whether the key signs a digest of a message rather than the message, which its parameter set names. */
    private static boolean signsADigest(String parameterSet) {
        return parameterSet.toUpperCase(Locale.ROOT).contains(PREHASH_MARKER);
    }

    /**
     * Which curve the key is on, matched by the identifier the curve is registered under.
     *
     * <p>
     * Neither its field nor its name identifies it. Several curves share a field size, so matching on the size alone
     * recorded a key on {@code secp256k1} as a key on {@code secp256r1} — a row naming a curve the key is not on, and
     * that name is the reference the platform holds for the key. And one curve answers to several names, so matching on
     * the name alone refuses a key on {@code prime256v1}, which is the same curve as {@code secp256r1}. The identifier
     * is what every name for a curve agrees on and no two curves share. A curve this provider does not offer is
     * refused.
     * </p>
     */
    static EcdsaCurveName curveOf(KeyPair keyPair) {
        String named = namedCurveOf(keyPair);
        ASN1ObjectIdentifier stated = ECNamedCurveTable.getOID(named);
        if (stated == null) {
            throw unsupported("the curve " + named);
        }
        return Stream
                .of(EcdsaCurveName.values())
                .filter(curve -> stated.equals(ECNamedCurveTable.getOID(curve.getName())))
                .findFirst()
                .orElseThrow(() -> unsupported("the curve " + named));
    }

    /** The curve the key states, which is a name for every curve this provider offers. */
    private static String namedCurveOf(KeyPair keyPair) {
        ECParameterSpec parameters = ((ECPrivateKey) keyPair.getPrivate()).getParams();
        if (parameters instanceof ECNamedCurveSpec named) {
            return named.getName();
        }
        throw unsupported("a curve of its own rather than a named one");
    }

    private static FalconDegree degreeOf(String parameterSet) {
        return matching(Stream.of(FalconDegree.values()),
                degree -> parameterSet.endsWith(String.valueOf(degree.getDegree())), parameterSet);
    }

    private static MLDSASecurityCategory mlDsaCategoryOf(String parameterSet) {
        return matching(Stream.of(MLDSASecurityCategory.values()),
                category -> parameterSet.contains("-" + category.getParameterSet()), parameterSet);
    }

    private static SLHDSASecurityCategory slhDsaCategoryOf(String parameterSet) {
        return matching(Stream.of(SLHDSASecurityCategory.values()),
                category -> parameterSet.contains("-" + category.getSecurityParameterLength()), parameterSet);
    }

    private static SLHDSAHash slhDsaHashOf(String parameterSet) {
        return matching(Stream.of(SLHDSAHash.values()),
                hash -> parameterSet.toUpperCase(Locale.ROOT).contains("-" + hash.getHashName() + "-"), parameterSet);
    }

    /**
     * Whether the key is the fast or the small form, which its parameter set states as the letter after the size of its
     * security parameter.
     */
    private static SLHDSASignatureMode slhDsaModeOf(String parameterSet) {
        String sized = "-" + slhDsaCategoryOf(parameterSet).getSecurityParameterLength();
        int after = parameterSet.indexOf(sized) + sized.length();
        String stated = after < parameterSet.length() ? parameterSet.substring(after, after + 1) : "";
        return matching(Stream.of(SLHDSASignatureMode.values()),
                mode -> mode.getParameterName().equalsIgnoreCase(stated), parameterSet);
    }

    private static MLKEMSecurityCategory mlKemCategoryOf(String parameterSet) {
        return matching(Stream.of(MLKEMSecurityCategory.values()),
                category -> parameterSet.equals(category.getParameterSet()), parameterSet);
    }

    private static <T> T matching(Stream<T> known, Predicate<T> states, String parameterSet) {
        return known.filter(states).findFirst().orElseThrow(() -> unsupported("the parameter set " + parameterSet));
    }

    /**
     * Why the key cannot be described. Everything described here arrived as imported material, and a parameter set this
     * provider does not offer is a key type it cannot take in, which the contract names.
     */
    private static KeyTypeNotImportableException unsupported(String what) {
        return new KeyTypeNotImportableException(
                "The key states " + what + ", which cannot be imported into this token");
    }
}
