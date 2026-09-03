package com.otilm.cp.soft.service;

import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.connector.cryptography.v2.key.CreateKeyAttributesRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.CreateKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.DestroyKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairDataResponseV2Dto;
import java.util.List;

/**
 * The key lifecycle as the V2 interfaces present it.
 */
public interface CryptographicKeyV2Service {

    /**
     * The attribute schema for creating a key of the requested type.
     *
     * @param request the token context and the key type
     * @return the attribute schema
     */
    List<BaseAttribute> createKeyAttributes(CreateKeyAttributesRequestV2Dto request);

    /**
     * Creates a key pair, or returns the one an earlier attempt with the same creation identifier made.
     *
     * @param request the creation request
     * @return the created key pair
     */
    KeyPairDataResponseV2Dto createKey(CreateKeyRequestV2Dto request);

    /**
     * Destroys the key the request addresses.
     *
     * @param request the destruction request
     */
    void destroyKey(DestroyKeyRequestV2Dto request);
}
