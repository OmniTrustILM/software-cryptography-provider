package com.otilm.cp.soft.api.v2;

import com.otilm.api.interfaces.connector.cryptography.v2.TokenController;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.connector.cryptography.v2.TokenProfileScopedRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.token.TokenScopedRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.token.TokenStatusResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.token.TokenStatusV2;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.cp.soft.model.TokenState;
import com.otilm.cp.soft.service.AttributeService;
import com.otilm.cp.soft.service.TokenContextService;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

/**
 * Serves the V2 token operations.
 *
 * <p>
 * The V2 interfaces have no operation that creates, activates or removes a token: a request carries the token as
 * attributes and the provider works out the rest. What is left here is the schema a token is configured with, the
 * schema and capabilities of a token profile, and whether the token a context addresses can be used.
 * </p>
 */
@RestController
public class TokenV2ControllerImpl implements TokenController {

    private static final Logger logger = LoggerFactory.getLogger(TokenV2ControllerImpl.class);

    /** Kind of token this connector provides, and the only one its attribute schema describes. */
    private static final String KIND = "SOFT";

    /**
     * Usages a key of this provider can serve. It signs, verifies, encrypts and decrypts; it does not wrap keys, so
     * offering those usages would have the platform create keys for operations this provider cannot perform.
     */
    private static final List<KeyUsage> KEY_USAGES = List
            .of(KeyUsage.SIGN, KeyUsage.VERIFY, KeyUsage.ENCRYPT, KeyUsage.DECRYPT);

    /** Secret keys are not implemented, so only key pairs are offered. */
    private static final List<KeyRequestType> KEY_REQUEST_TYPES = List.of(KeyRequestType.KEY_PAIR);

    private AttributeService attributeService;

    private TokenContextService tokenContextService;

    @Override
    public List<BaseAttribute> listTokenAttributes() {
        return attributeService.getAttributes(KIND);
    }

    @Override
    public TokenStatusResponseV2Dto getTokenStatus(TokenScopedRequestV2Dto request) {
        TokenState state = tokenContextService.inspect(request.getTokenAttributes());
        logger.debug("A token status request found the token {}", state.availability());

        TokenStatusResponseV2Dto status = new TokenStatusResponseV2Dto();
        status.setStatus(switch (state.availability()) {
            case AVAILABLE -> TokenStatusV2.CONNECTED;
            case MISSING, UNUSABLE -> TokenStatusV2.DISCONNECTED;
        });
        status.setDetail(state.detail());
        return status;
    }

    @Override
    public List<BaseAttribute> listTokenProfileAttributes(TokenScopedRequestV2Dto request) {
        return List.of();
    }

    @Override
    public List<KeyUsage> listTokenProfileKeyUsages(TokenScopedRequestV2Dto request) {
        return KEY_USAGES;
    }

    @Override
    public List<KeyRequestType> listSupportedKeyRequestTypes(TokenProfileScopedRequestV2Dto request) {
        return KEY_REQUEST_TYPES;
    }

    @Autowired
    public void setAttributeService(AttributeService attributeService) {
        this.attributeService = attributeService;
    }

    @Autowired
    public void setTokenContextService(TokenContextService tokenContextService) {
        this.tokenContextService = tokenContextService;
    }
}
