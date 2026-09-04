package com.otilm.cp.soft.testsupport;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.RsaSignatureScheme;
import com.otilm.api.model.connector.common.v2.OperationExecutionMode;
import com.otilm.api.model.connector.cryptography.v2.OperationTrackingRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ImportKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.material.EncryptedKeyMaterialV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.SignDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.SignDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.VerifyDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.data.SignatureDataV2Dto;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.cp.soft.api.v2.OperationsV2ControllerImpl;
import com.otilm.cp.soft.attribute.KeyAttributes;
import com.otilm.cp.soft.attribute.RsaKeyAttributes;
import com.otilm.cp.soft.util.KeyStoreUtil;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Import requests carrying key material the platform would have sent.
 *
 * <p>
 * The platform re-protects whatever a user supplied before it reaches a connector, so a request here is built the same
 * way: a key is generated, taken out as protected material, and imported under a passphrase generated for that one
 * request.
 * </p>
 */
public final class KeyImportFixtures {

    private static final String CODE = "00000000";

    private static final byte[] MESSAGE = "the message to sign".getBytes(StandardCharsets.UTF_8);

    /** The passphrase the platform generates for one import, which travels beside the material. */
    public static final String PASSPHRASE = KeyMaterialFixtures.PASSPHRASE;

    private KeyImportFixtures() {
    }

    /** A request importing a 2048-bit RSA key pair into a token of the given name. */
    public static ImportKeyRequestV2Dto rsaImport(String tokenName) {
        ImportKeyRequestV2Dto request = new ImportKeyRequestV2Dto();
        request.setTokenAttributes(TokenContextFixtures.newToken(tokenName));
        request.setTokenProfileAttributes(List.of());
        request.setKeyUsages(Set.of(KeyUsage.SIGN, KeyUsage.VERIFY));
        request.setKeyRequestType(KeyRequestType.KEY_PAIR);
        request.setExecutionMode(OperationExecutionMode.SYNCHRONOUS);
        request.setKeyImportId(UUID.randomUUID().toString());
        request.setKeyReference(UUID.randomUUID().toString());
        request.setExportable(false);
        request
                .setImportKeyAttributes(List
                        .of(TokenContextFixtures
                                .string(KeyAttributes.ATTRIBUTE_DATA_KEY_ALIAS, "imported-" + System.nanoTime())));

        EncryptedKeyMaterialV2Dto material = new EncryptedKeyMaterialV2Dto();
        material.setEncryptedPrivateKeyInfo(KeyMaterialFixtures.protect(generatedRsaKey(), PASSPHRASE));
        request.setMaterial(material);
        request.setPassphrase(PASSPHRASE);
        return request;
    }

    /** A tracking request, for the operations that track nothing. */
    public static OperationTrackingRequestV2Dto tracking() {
        return new OperationTrackingRequestV2Dto();
    }

    /**
     * Whether a signature made with the imported private key verifies with its own public half, which is what makes an
     * imported key a key like any other.
     */
    public static boolean signsAndVerifies(OperationsV2ControllerImpl operations,
            List<RequestAttribute> tokenAttributes, List<MetadataAttribute> privateKeyMeta,
            List<MetadataAttribute> publicKeyMeta) {
        SignDataRequestV2Dto signing = new SignDataRequestV2Dto();
        signing.setTokenAttributes(tokenAttributes);
        signing.setKeyMeta(privateKeyMeta);
        signing.setExecutionMode(OperationExecutionMode.SYNCHRONOUS);
        signing.setSignatureAttributes(rsaSignatureAttributes());
        signing.setData(List.of(item("one", MESSAGE)));

        SignDataResponseV2Dto signed = operations.signData(signing).getBody();
        if (signed == null) {
            return false;
        }

        VerifyDataRequestV2Dto verification = new VerifyDataRequestV2Dto();
        verification.setTokenAttributes(tokenAttributes);
        verification.setKeyMeta(publicKeyMeta);
        verification.setSignatureAttributes(rsaSignatureAttributes());
        verification.setData(List.of(item("one", MESSAGE)));
        verification.setSignatures(signed.getSignatures());

        return operations.verifyData(verification).getVerifications().get(0).getResult();
    }

    /** The same request, carrying other material. Everything the platform states stays as it was. */
    public static ImportKeyRequestV2Dto sameRequestCarrying(ImportKeyRequestV2Dto original,
            EncryptedKeyMaterialV2Dto material) {
        ImportKeyRequestV2Dto repeat = new ImportKeyRequestV2Dto();
        repeat.setTokenAttributes(original.getTokenAttributes());
        repeat.setTokenProfileAttributes(original.getTokenProfileAttributes());
        repeat.setKeyUsages(original.getKeyUsages());
        repeat.setKeyRequestType(original.getKeyRequestType());
        repeat.setExecutionMode(original.getExecutionMode());
        repeat.setKeyImportId(original.getKeyImportId());
        repeat.setKeyReference(original.getKeyReference());
        repeat.setExportable(original.getExportable());
        repeat.setImportKeyAttributes(original.getImportKeyAttributes());
        repeat.setMaterial(material);
        repeat.setPassphrase(original.getPassphrase());
        return repeat;
    }

    /** Material holding a different key of the same algorithm, so only the key tells two requests apart. */
    public static EncryptedKeyMaterialV2Dto anotherKey() {
        EncryptedKeyMaterialV2Dto material = new EncryptedKeyMaterialV2Dto();
        material.setEncryptedPrivateKeyInfo(KeyMaterialFixtures.protect(generatedRsaKey(), PASSPHRASE));
        return material;
    }

    /** Material holding a key of an algorithm this provider does not hold. */
    public static EncryptedKeyMaterialV2Dto ed25519Material() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME);
            EncryptedKeyMaterialV2Dto material = new EncryptedKeyMaterialV2Dto();
            material
                    .setEncryptedPrivateKeyInfo(
                            KeyMaterialFixtures.protect(generator.generateKeyPair().getPrivate(), PASSPHRASE));
            return material;
        } catch (Exception e) {
            throw new IllegalStateException("Cannot generate a key of an unsupported algorithm", e);
        }
    }

    /** A key generated the way a user's own key would have been, before the platform protected it. */
    private static PrivateKey generatedRsaKey() {
        try {
            KeyStore keyStore = KeyStoreUtil.loadKeystore(KeyStoreUtil.createNewKeystore("PKCS12", CODE), CODE);
            KeyStoreUtil.generateRsaKey(keyStore, "source", 2048, CODE);
            return (PrivateKey) keyStore.getKey("source", CODE.toCharArray());
        } catch (Exception e) {
            throw new IllegalStateException("Cannot generate the key an import would carry", e);
        }
    }

    private static List<RequestAttribute> rsaSignatureAttributes() {
        return List
                .of(TokenContextFixtures
                        .string(RsaKeyAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME,
                                RsaSignatureScheme.PKCS1_v1_5.getCode()),
                        TokenContextFixtures
                                .string(RsaKeyAttributes.ATTRIBUTE_DATA_SIG_DIGEST, DigestAlgorithm.SHA_256.getCode()));
    }

    private static SignatureDataV2Dto item(String identifier, byte[] data) {
        SignatureDataV2Dto signature = new SignatureDataV2Dto();
        signature.setIdentifier(identifier);
        signature.setData(data);
        return signature;
    }
}
