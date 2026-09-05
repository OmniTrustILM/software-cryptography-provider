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

    /**
     * What a key creation asks for, which is the same whichever token the key is going into.
     *
     * <p>
     * The V2 interfaces answer this without a token: a context asking for one by name has nothing to look up yet, and
     * describing what a creation asks for is not a reason to bring a token into existence.
     * </p>
     *
     * @return the attributes a key creation asks for
     */
    List<BaseAttribute> getCreateKeyAttributes();

    boolean validateCreateKeyAttributes(String uuid, List<RequestAttribute> attributes) throws NotFoundException;

}
