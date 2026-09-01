package com.otilm.cp.soft.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.BaseAttribute;

import java.util.List;

public interface AttributeService {

    List<BaseAttribute> getAttributes(String kind);

    boolean validateAttributes(String kind, List<RequestAttribute> attributes);

    List<BaseAttribute> getTokenInstanceActivationAttributes(String uuid);

    boolean validateTokenInstanceActivationAttributes(String uuid, List<RequestAttribute> attributes);

    List<BaseAttribute> getCreateKeyAttributes(String uuid) throws NotFoundException;

    boolean validateCreateKeyAttributes(String uuid, List<RequestAttribute> attributes) throws NotFoundException;

}
