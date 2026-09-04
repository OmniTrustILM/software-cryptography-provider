package com.otilm.cp.soft.testsupport;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.cryptography.v2.material.EncryptedKeyMaterialV2Dto;
import com.otilm.cp.soft.util.ImportedKeyMaterial;
import java.nio.file.Path;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The collection carries key material so an import can be exercised without the platform. A blob nobody can decrypt
 * would fail only when someone tried it by hand, so what is committed is opened here.
 */
@SpringBootTest
class SampleImportMaterialTest {

    private static final Path ENVIRONMENT = Path
            .of("docs", "postman", "software-cryptography-provider.postman_environment.json");

    @Test
    void opensTheMaterialTheCollectionCarries() throws Exception {
        // given
        JsonNode values = new ObjectMapper().readTree(ENVIRONMENT.toFile()).get("values");
        byte[] envelope = Base64.getDecoder().decode(valueOf(values, "importMaterial"));
        String passphrase = valueOf(values, "importPassphrase");

        // when
        EncryptedKeyMaterialV2Dto material = new EncryptedKeyMaterialV2Dto();
        material.setEncryptedPrivateKeyInfo(envelope);
        ImportedKeyMaterial opened = ImportedKeyMaterial.open(envelope, passphrase);

        // then
        assertTrue(material.isCanonicalEnvelope(), "the committed envelope must be canonical DER");
        assertTrue(material.isPinnedProtectionScheme(), "the committed envelope must sit in the pinned profile");
        assertTrue(material.isPinnedProtectionParameters(), "its salt, iterations and vector must sit in range");
        assertEquals(KeyAlgorithm.RSA, opened.algorithm());
        assertEquals(2048,
                ((java.security.interfaces.RSAPublicKey) opened.keyPair().getPublic()).getModulus().bitLength());
    }

    private static String valueOf(JsonNode values, String key) {
        for (JsonNode value : values) {
            if (key.equals(value.get("key").asText())) {
                return value.get("value").asText();
            }
        }
        throw new IllegalStateException("The collection environment states no " + key);
    }
}
