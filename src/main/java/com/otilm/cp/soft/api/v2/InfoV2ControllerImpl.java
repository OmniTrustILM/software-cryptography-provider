package com.otilm.cp.soft.api.v2;

import com.otilm.api.interfaces.connector.common.v2.InfoController;
import com.otilm.api.model.client.connector.v2.ConnectorInfo;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorInterfaceInfo;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.connector.v2.InfoResponse;
import java.util.List;
import org.springframework.boot.info.BuildProperties;
import org.springframework.web.bind.annotation.RestController;

/**
 * Reports what this connector serves under the V2 interfaces.
 *
 * <p>
 * A declared feature flag is enforced against the connector afterwards, so this describes the code as it stands rather
 * than what the provider could grow into. Asynchronous execution is deliberately absent: every operation here completes
 * inline, so offering it would only have the platform send requests this connector refuses. Key export is absent for
 * the same reason, which is also why an import asking for a key that stays exportable is refused.
 * </p>
 */
@RestController
public class InfoV2ControllerImpl implements InfoController {

    /** Version of the cryptography provider interface this connector implements. */
    private static final String CRYPTOGRAPHY_INTERFACE_VERSION = "v2";

    /** Version of the common connector interfaces, whose generation is itself the v2 in their package. */
    private static final String COMMON_INTERFACE_VERSION = "v2";

    private final BuildProperties buildProperties;

    public InfoV2ControllerImpl(BuildProperties buildProperties) {
        this.buildProperties = buildProperties;
    }

    @Override
    public InfoResponse getConnectorInfo() {
        InfoResponse info = new InfoResponse();
        info.setConnector(connector());
        info
                .setInterfaces(List
                        .of(common(ConnectorInterface.INFO), common(ConnectorInterface.HEALTH),
                                common(ConnectorInterface.ATTRIBUTES), cryptography()));
        return info;
    }

    private ConnectorInfo connector() {
        ConnectorInfo connector = new ConnectorInfo();
        connector.setId(buildProperties.getArtifact());
        connector.setName(buildProperties.getName());
        connector.setVersion(buildProperties.getVersion());
        connector.setDescription("Software cryptography provider storing key material in PKCS12 keystores");
        return connector;
    }

    private static ConnectorInterfaceInfo common(ConnectorInterface code) {
        return new ConnectorInterfaceInfo(code, COMMON_INTERFACE_VERSION, List.of());
    }

    private static ConnectorInterfaceInfo cryptography() {
        return new ConnectorInterfaceInfo(ConnectorInterface.CRYPTOGRAPHY, CRYPTOGRAPHY_INTERFACE_VERSION,
                List.of(FeatureFlag.KEY_IMPORT));
    }
}
