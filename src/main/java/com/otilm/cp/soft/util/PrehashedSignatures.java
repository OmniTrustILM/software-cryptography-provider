package com.otilm.cp.soft.util;

import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
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
     * @throws IllegalArgumentException when the algorithm is outside what can be signed as a digest, or the digest is
     * not exactly the length of the algorithm's hash
     * @throws IllegalStateException when the signer cannot be set up for this key
     */
    public static byte[] sign(SignatureAlgorithm algorithm, PrivateKey key, byte[] digest) throws SignatureException {
        DigestAlgorithm hash = SignatureAlgorithms.digestOf(algorithm);
        if (hash == null) {
            throw new IllegalArgumentException("A digest cannot be signed under " + algorithm.getCode());
        }
        if (digest.length != hash.getDigestSizeBytes()) {
            throw new IllegalArgumentException(
                    "A " + hash.getCode() + " digest is " + hash.getDigestSizeBytes() + " bytes, not " + digest.length);
        }
        try {
            // The scheme comes from the tables the data path offers and signs by, so the two paths cannot disagree.
            if (SignatureAlgorithms.isRsaPss(algorithm)) {
                return signPss(hash, key, digest);
            }
            if (SignatureAlgorithms.offeredFor(KeyAlgorithm.ECDSA).contains(algorithm)) {
                return signUnhashed("NONEwithECDSA", key, digest);
            }
            return signUnhashed("NONEwithRSA", key, derDigestInfo(hash, digest));
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

    private static byte[] signUnhashed(String name, PrivateKey key, byte[] input) throws GeneralSecurityException {
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
