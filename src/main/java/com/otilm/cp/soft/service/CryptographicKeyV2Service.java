package com.otilm.cp.soft.service;

import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.connector.cryptography.v2.KeyScopedRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.TokenProfileScopedRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.CreateKeyAttributesRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.CreateKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.DestroyKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ExportKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ExportKeyResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ExportableKeyTypeV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ImportKeyAttributesRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ImportKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ImportKeyResultRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ImportableKeyTypeV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairOperationStatusResponseV2Dto;
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

    /**
     * The key types and algorithms this connector accepts as imported material for the addressed token.
     *
     * @param request the token context
     * @return one declaration per key type that can be imported
     */
    List<ImportableKeyTypeV2Dto> importableKeyTypes(TokenProfileScopedRequestV2Dto request);

    /**
     * The schema of the attributes an import accepts.
     *
     * @param request the token context and the key type to import
     * @return the attribute definitions
     */
    List<BaseAttribute> importKeyAttributes(ImportKeyAttributesRequestV2Dto request);

    /**
     * Brings a key the platform sent into the addressed token.
     *
     * @param request the material, the passphrase protecting it, and the terms to import it on
     * @return the imported key pair, with a handle published for each half
     */
    KeyPairDataResponseV2Dto importKey(ImportKeyRequestV2Dto request);

    /**
     * What became of an import, for a caller that never heard its answer.
     *
     * @param request the token context and the identifier the import was asked under
     * @return the import's outcome, carrying the key when it completed
     */
    KeyPairOperationStatusResponseV2Dto importResult(ImportKeyResultRequestV2Dto request);

    /**
     * The key types and algorithms this connector lets out of the addressed token.
     *
     * @param request the token context
     * @return one declaration per key type that can be exported
     */
    List<ExportableKeyTypeV2Dto> exportableKeyTypes(TokenProfileScopedRequestV2Dto request);

    /**
     * The schema of the attributes an export accepts.
     *
     * @param request the token context and the key to export
     * @return the attribute definitions
     */
    List<BaseAttribute> exportKeyAttributes(KeyScopedRequestV2Dto request);

    /**
     * Takes a key out of the addressed token, protected under the passphrase the request carries.
     *
     * @param request the key to export and the passphrase to protect it under
     * @return the protected material and a description of what was exported
     */
    ExportKeyResponseV2Dto exportKey(ExportKeyRequestV2Dto request);
}
