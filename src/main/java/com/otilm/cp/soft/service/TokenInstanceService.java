package com.otilm.cp.soft.service;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.connector.cryptography.token.TokenInstanceDto;
import com.otilm.api.model.connector.cryptography.token.TokenInstanceRequestDto;
import com.otilm.api.model.connector.cryptography.token.TokenInstanceStatusDto;
import com.otilm.cp.soft.dao.entity.TokenInstance;

import java.util.List;
import java.util.UUID;

public interface TokenInstanceService {

    List<TokenInstanceDto> listTokenInstances();

    TokenInstanceDto getTokenInstance(UUID uuid) throws NotFoundException;

    TokenInstance getTokenInstanceEntity(UUID uuid) throws NotFoundException;

    TokenInstanceDto createTokenInstance(TokenInstanceRequestDto request) throws AlreadyExistException;

    void removeTokenInstance(UUID uuid) throws NotFoundException;

    TokenInstanceStatusDto getTokenInstanceStatus(UUID uuid) throws NotFoundException;

    void activateTokenInstance(UUID uuid, List<RequestAttribute> attributes) throws NotFoundException;

    void deactivateTokenInstance(UUID uuid) throws NotFoundException;

    boolean containsTokens();

    void saveTokenInstance(TokenInstance tokenInstance);

}
