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
 * inline, so offering it would only have the platform send requests this connector refuses.
 * </p>
 */
@RestController
public class InfoV2ControllerImpl implements InfoController {

    /** Version of the cryptography provider interface this connector implements. */
    private static final String CRYPTOGRAPHY_INTERFACE_VERSION = "v2";

    /** Version of the common connector interfaces, whose generation is itself the v2 in their package. */
    private static final String COMMON_INTERFACE_VERSION = "v2";

    /** Version of the metrics interface, which the contract numbers on its own and serves under that number. */
    private static final String METRICS_INTERFACE_VERSION = "v1";

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
                        .of(common(ConnectorInterface.INFO), common(ConnectorInterface.HEALTH), metrics(),
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

    /** The metrics interface, whose OpenMetrics exposition format a connector serving it has to declare. */
    private static ConnectorInterfaceInfo metrics() {
        return new ConnectorInterfaceInfo(ConnectorInterface.METRICS, METRICS_INTERFACE_VERSION,
                List.of(FeatureFlag.OPEN_METRICS));
    }

    private static ConnectorInterfaceInfo cryptography() {
        return new ConnectorInterfaceInfo(ConnectorInterface.CRYPTOGRAPHY, CRYPTOGRAPHY_INTERFACE_VERSION,
                List.of(FeatureFlag.KEY_IMPORT, FeatureFlag.KEY_EXPORT));
    }
}
