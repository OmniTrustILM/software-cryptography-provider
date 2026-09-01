package com.otilm.cp.soft.api;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.connector.cryptography.TokenInstanceController;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.connector.cryptography.token.TokenInstanceDto;
import com.otilm.api.model.connector.cryptography.token.TokenInstanceRequestDto;
import com.otilm.api.model.connector.cryptography.token.TokenInstanceStatusDto;
import com.otilm.cp.soft.exception.NotSupportedException;
import com.otilm.cp.soft.service.AttributeService;
import com.otilm.cp.soft.service.TokenInstanceService;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TokenInstanceControllerImpl implements TokenInstanceController {

    private TokenInstanceService tokenInstanceService;

    private AttributeService attributeService;

    @Autowired
    public void setTokenInstanceService(TokenInstanceService tokenInstanceService) {
        this.tokenInstanceService = tokenInstanceService;
    }

    @Autowired
    public void setAttributeService(AttributeService attributeService) {
        this.attributeService = attributeService;
    }

    @Override
    public List<TokenInstanceDto> listTokenInstances() {
        return tokenInstanceService.listTokenInstances();
    }

    @Override
    public TokenInstanceDto getTokenInstance(String uuid) throws NotFoundException {
        return tokenInstanceService.getTokenInstance(UUID.fromString(uuid));
    }

    @Override
    public TokenInstanceDto createTokenInstance(TokenInstanceRequestDto request) throws AlreadyExistException {
        if (!attributeService.validateAttributes(request.getKind(), request.getAttributes())) {
            throw new ValidationException("Token instance attributes validation failed.");
        }
        return tokenInstanceService.createTokenInstance(request);
    }

    @Override
    public TokenInstanceDto updateTokenInstance(String uuid, TokenInstanceRequestDto request) throws NotFoundException {
        throw new NotSupportedException("Update Token instance not supported");
    }

    @Override
    public void removeTokenInstance(String uuid) throws NotFoundException {
        tokenInstanceService.removeTokenInstance(UUID.fromString(uuid));
    }

    @Override
    public TokenInstanceStatusDto getTokenInstanceStatus(String uuid) throws NotFoundException {
        return tokenInstanceService.getTokenInstanceStatus(UUID.fromString(uuid));
    }

    @Override
    public List<BaseAttribute> listTokenProfileAttributes(String uuid) throws NotFoundException {
        // there are no attributes needed for token profile
        return List.of();
    }

    @Override
    public void validateTokenProfileAttributes(String uuid, List<RequestAttribute> attributes)
            throws ValidationException, NotFoundException {
        // there are no attributes needed for token profile
    }

    @Override
    public List<BaseAttribute> listTokenInstanceActivationAttributes(String uuid) throws NotFoundException {
        return attributeService.getTokenInstanceActivationAttributes(uuid);
    }

    @Override
    public void validateTokenInstanceActivationAttributes(String uuid, List<RequestAttribute> attributes)
            throws ValidationException, NotFoundException {
        attributeService.validateTokenInstanceActivationAttributes(uuid, attributes);
    }

    @Override
    public void activateTokenInstance(String uuid, List<RequestAttribute> attributes) throws NotFoundException {
        if (!attributeService.validateTokenInstanceActivationAttributes(uuid, attributes)) {
            throw new ValidationException("Token instance attributes validation failed.");
        }
        tokenInstanceService.activateTokenInstance(UUID.fromString(uuid), attributes);
    }

    @Override
    public void deactivateTokenInstance(String uuid) throws NotFoundException {
        tokenInstanceService.deactivateTokenInstance(UUID.fromString(uuid));
    }
}
