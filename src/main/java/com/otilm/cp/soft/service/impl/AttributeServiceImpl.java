package com.otilm.cp.soft.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.otilm.cp.soft.attribute.KeyAttributes;
import com.otilm.cp.soft.attribute.TokenInstanceActivationAttributes;
import com.otilm.cp.soft.attribute.TokenInstanceAttributes;
import com.otilm.cp.soft.service.AttributeService;
import com.otilm.cp.soft.service.TokenInstanceService;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AttributeServiceImpl implements AttributeService {
    private static final Logger logger = LoggerFactory.getLogger(AttributeServiceImpl.class);

    private TokenInstanceService tokenInstanceService;

    @Autowired
    public void setTokenInstanceService(TokenInstanceService tokenInstanceService) {
        this.tokenInstanceService = tokenInstanceService;
    }

    @Override
    public List<BaseAttribute> getAttributes(String kind) {
        logger.debug("Getting the attributes for {}", kind);

        // when we do not have Tokens, return attributes to create new
        if (tokenInstanceService.listTokenInstances() == null) {
            return TokenInstanceAttributes.getNewTokenAttributes();
        } else {
            List<BaseAttribute> attrs = new ArrayList<>();

            // first attribute is to select from existing tokens, or create a new one
            attrs.add(TokenInstanceAttributes.buildInitialInfo());
            // create options to add new Token
            attrs.add(TokenInstanceAttributes.buildOptions());
            // load additional Attributes for the selected Token
            attrs.add(TokenInstanceAttributes.buildGroupBasedOnSelect());

            return attrs;
        }
    }

    @Override
    public boolean validateAttributes(String kind, List<RequestAttribute> attributes) {
        if (attributes == null) {
            return false;
        }

        AttributeDefinitionUtils.validateAttributes(getAttributes(kind), attributes);
        return true;
    }

    @Override
    public List<BaseAttribute> getTokenInstanceActivationAttributes(String uuid) {
        logger.debug("Getting Token instance activation attributes for {}", uuid);

        List<BaseAttribute> attrs = new ArrayList<>();

        attrs.add(TokenInstanceActivationAttributes.buildDataTokenActivationCode());

        return attrs;
    }

    @Override
    public boolean validateTokenInstanceActivationAttributes(String uuid, List<RequestAttribute> attributes) {
        if (attributes == null) {
            return false;
        }

        AttributeDefinitionUtils.validateAttributes(getTokenInstanceActivationAttributes(uuid), attributes);
        return true;
    }

    @Override
    public List<BaseAttribute> getCreateKeyAttributes(String uuid) throws NotFoundException {
        tokenInstanceService.getTokenInstance(UUID.fromString(uuid));
        return getCreateKeyAttributes();
    }

    @Override
    public List<BaseAttribute> getCreateKeyAttributes() {
        List<BaseAttribute> attrs = new ArrayList<>();

        attrs.add(KeyAttributes.buildDataKeyAlias());
        attrs.add(KeyAttributes.buildDataKeyAlgorithmSelect());
        attrs.add(KeyAttributes.buildGroupKeyAttributesBasedOnSelectedAlgorithm());

        return attrs;
    }

    @Override
    public boolean validateCreateKeyAttributes(String uuid, List<RequestAttribute> attributes)
            throws NotFoundException {
        if (attributes == null) {
            return false;
        }

        tokenInstanceService.getTokenInstance(UUID.fromString(uuid));

        AttributeDefinitionUtils.validateAttributes(getCreateKeyAttributes(uuid), attributes);
        return true;
    }

}
