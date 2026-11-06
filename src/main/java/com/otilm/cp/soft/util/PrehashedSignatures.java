package com.otilm.cp.soft.util;

import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.EnumSet;
import java.util.Set;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Signs a digest the caller already computed, for the RSA and ECDSA algorithms whose signature is defined over a hash.
 * The digest is signed as it stands, so it is never hashed again.
 */
public final class PrehashedSignatures {

    private static final Set<SignatureAlgorithm> RSA_PSS = EnumSet
            .of(SignatureAlgorithm.SHA256_WITH_RSA_PSS, SignatureAlgorithm.SHA384_WITH_RSA_PSS,
                    SignatureAlgorithm.SHA512_WITH_RSA_PSS);

    private static final Set<SignatureAlgorithm> ECDSA = EnumSet
            .of(SignatureAlgorithm.SHA256_WITH_ECDSA, SignatureAlgorithm.SHA384_WITH_ECDSA,
                    SignatureAlgorithm.SHA512_WITH_ECDSA);

    private static final String PROVIDER = BouncyCastleProvider.PROVIDER_NAME;

    private PrehashedSignatures() {
    }

    /**
     * Whether a digest can be signed under the algorithm.
     *
     * @param algorithm the signature algorithm
     * @return true for the RSA and ECDSA algorithms that name a digest
     */
    public static boolean admits(SignatureAlgorithm algorithm) {
        return SignatureAlgorithms.digestOf(algorithm) != null;
    }

    /**
     * Signs the digest with the key.
     *
     * @param algorithm the signature algorithm, one that {@link #admits} accepts
     * @param key the private key
     * @param digest the digest to sign
     * @return the signature
     * @throws SignatureException when the signer rejects the digest
     * @throws IllegalArgumentException when the algorithm is outside what can be signed as a digest
     * @throws IllegalStateException when the signer cannot be set up for this key
     */
    public static byte[] sign(SignatureAlgorithm algorithm, PrivateKey key, byte[] digest) throws SignatureException {
        DigestAlgorithm hash = SignatureAlgorithms.digestOf(algorithm);
        if (hash == null) {
            throw new IllegalArgumentException("A digest cannot be signed under " + algorithm.getCode());
        }
        try {
            if (RSA_PSS.contains(algorithm)) {
                return signPss(hash, key, digest);
            }
            if (ECDSA.contains(algorithm)) {
                return signRaw("NONEwithECDSA", key, digest);
            }
            return signRaw("NONEwithRSA", key, derDigestInfo(hash, digest));
        } catch (SignatureException e) {
            throw e;
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalStateException("The signer could not be set up", e);
        }
    }

    private static byte[] signPss(DigestAlgorithm hash, PrivateKey key, byte[] digest) throws GeneralSecurityException {
        String name = hash.getCode();
        Signature signer = Signature.getInstance("RAWRSASSA-PSS", PROVIDER);
        signer
                .setParameter(
                        new PSSParameterSpec(name, "MGF1", new MGF1ParameterSpec(name), hash.getDigestSizeBytes(), 1));
        return signWith(signer, key, digest);
    }

    private static byte[] signRaw(String name, PrivateKey key, byte[] input) throws GeneralSecurityException {
        return signWith(Signature.getInstance(name, PROVIDER), key, input);
    }

    private static byte[] signWith(Signature signer, PrivateKey key, byte[] input) throws GeneralSecurityException {
        signer.initSign(key);
        signer.update(input);
        return signer.sign();
    }

    private static byte[] derDigestInfo(DigestAlgorithm hash, byte[] digest) throws IOException {
        AlgorithmIdentifier algorithm = new AlgorithmIdentifier(new ASN1ObjectIdentifier(hash.getOid()),
                DERNull.INSTANCE);
        return new DigestInfo(algorithm, digest).getEncoded("DER");
    }
}
