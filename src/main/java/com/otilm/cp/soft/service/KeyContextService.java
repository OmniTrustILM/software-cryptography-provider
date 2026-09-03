package com.otilm.cp.soft.service;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.cp.soft.dao.entity.KeyData;
import com.otilm.cp.soft.model.KeyContext;
import java.util.List;

/**
 * Turns the key metadata a V2 request carries into the key the provider works with, and publishes the metadata a caller
 * sends back to address that key again.
 */
public interface KeyContextService {

    /**
     * Resolves the key the metadata addresses, within the token the attributes address.
     *
     * @param tokenAttributes the token attributes supplied with the request
     * @param keyMeta the key metadata the connector published when the key was created
     * @return the key and its token
     */
    KeyContext resolve(List<RequestAttribute> tokenAttributes, List<MetadataAttribute> keyMeta);

    /**
     * The metadata that addresses a key on later requests.
     *
     * @param key the key to describe
     * @return the metadata identifying the key durably
     */
    List<MetadataAttribute> publish(KeyData key);
}
