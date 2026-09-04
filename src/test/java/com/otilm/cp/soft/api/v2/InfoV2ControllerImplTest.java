package com.otilm.cp.soft.api.v2;

import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorInterfaceInfo;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.connector.v2.InfoResponse;
import java.util.List;
import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.springframework.boot.info.BuildProperties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The V2 info response is how Core learns which interfaces this connector serves and what it can do. A feature flag it
 * declares is enforced against it afterwards, so the list has to describe the code as it stands.
 */
class InfoV2ControllerImplTest {

    private final InfoV2ControllerImpl controller = new InfoV2ControllerImpl(buildProperties());

    @Test
    void reportsTheConnectorIdentityFromTheBuild() {
        // given
        // when
        InfoResponse info = controller.getConnectorInfo();

        // then
        assertNotNull(info.getConnector());
        assertEquals("software-cryptography-provider", info.getConnector().getId());
        assertEquals("ILM-Software-Cryptography-Provider", info.getConnector().getName());
        assertEquals("1.4.0-SNAPSHOT", info.getConnector().getVersion());
    }

    @Test
    void declaresTheCryptographyInterfaceAtVersionTwo() {
        // given
        // when
        ConnectorInterfaceInfo cryptography = interfaceInfo(ConnectorInterface.CRYPTOGRAPHY);

        // then
        assertEquals("v2", cryptography.getVersion());
    }

    @Test
    void declaresTheCommonInterfacesItServes() {
        // given
        // when
        List<ConnectorInterface> declared = controller
                .getConnectorInfo()
                .getInterfaces()
                .stream()
                .map(ConnectorInterfaceInfo::getCode)
                .toList();

        // then
        assertTrue(
                declared
                        .containsAll(List
                                .of(ConnectorInterface.INFO, ConnectorInterface.HEALTH, ConnectorInterface.ATTRIBUTES,
                                        ConnectorInterface.CRYPTOGRAPHY)),
                () -> "expected the served interfaces, got " + declared);
    }

    /**
     * Every operation this provider performs completes inline, so asynchronous execution is deliberately not offered:
     * declaring it would have the platform send requests the connector answers by refusing them.
     */
    @Test
    void doesNotDeclareAsynchronousExecution() {
        // given
        // when
        List<FeatureFlag> features = interfaceInfo(ConnectorInterface.CRYPTOGRAPHY).getFeatures();

        // then
        assertNotNull(features, "the cryptography interface must state its features, even when empty");
        assertFalse(features.contains(FeatureFlag.ASYNCHRONOUS));
    }

    /**
     * A key can be brought in but not taken out, and a declared flag is enforced against the connector afterwards, so
     * only the one it performs is declared. Declaring export would have the platform send requests this refuses, and
     * would also have it offer keys that stay exportable, which an import cannot honour.
     */
    @Test
    void declaresKeyImportAndNotKeyExport() {
        // given
        // when
        List<FeatureFlag> features = interfaceInfo(ConnectorInterface.CRYPTOGRAPHY).getFeatures();

        // then
        assertTrue(features.contains(FeatureFlag.KEY_IMPORT));
        assertFalse(features.contains(FeatureFlag.KEY_EXPORT));
    }

    private ConnectorInterfaceInfo interfaceInfo(ConnectorInterface code) {
        return controller
                .getConnectorInfo()
                .getInterfaces()
                .stream()
                .filter(declared -> declared.getCode() == code)
                .findFirst()
                .orElseThrow(() -> new AssertionError(code + " is not declared"));
    }

    private static BuildProperties buildProperties() {
        Properties properties = new Properties();
        properties.setProperty("artifact", "software-cryptography-provider");
        properties.setProperty("name", "ILM-Software-Cryptography-Provider");
        properties.setProperty("version", "1.4.0-SNAPSHOT");
        return new BuildProperties(properties);
    }
}
