package com.otilm.cp.soft.service;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.cp.soft.dao.entity.KeyData;
import com.otilm.cp.soft.model.KeyContext;
import com.otilm.cp.soft.model.OperationKey;
import java.util.List;

/**
 * Turns the key metadata a V2 request carries into the key the provider works with.
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
     * Resolves the addressed key with its token's material and holds the request to the token's code. A token not
     * usable yet goes through {@link TokenContextService#resolve}, in one transaction with the key read.
     *
     * @param tokenAttributes the token attributes supplied with the request
     * @param keyMeta the key metadata the connector published when the key was created
     * @return the key and the material of its token
     */
    OperationKey resolveForOperation(List<RequestAttribute> tokenAttributes, List<MetadataAttribute> keyMeta);

    /**
     * The metadata that addresses a key pair on later requests.
     *
     * @param key either half of the pair
     * @return the pair's metadata
     */
    List<MetadataAttribute> publishPair(KeyData key);

    /**
     * The metadata that addresses a key on later requests.
     *
     * @param key the key to describe
     * @return the metadata identifying the key durably
     */
    List<MetadataAttribute> publish(KeyData key);
}
