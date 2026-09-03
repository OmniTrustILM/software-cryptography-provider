package com.otilm.cp.soft.service;

import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.connector.cryptography.v2.KeyScopedRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.TokenProfileScopedRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.CipherDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.DecryptDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.EncryptDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.RandomDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.RandomDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.SignDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.SignDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.VerifyDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.VerifyDataResponseV2Dto;
import java.util.List;

/**
 * The cryptographic operations as the V2 interfaces present them.
 */
public interface CryptographicOperationsV2Service {

    /**
     * What signing or verifying with the addressed key needs to be told.
     *
     * @param request the token and key context
     * @return the attribute schema
     */
    List<BaseAttribute> signatureAttributes(KeyScopedRequestV2Dto request);

    /**
     * What encrypting or decrypting with the addressed key needs to be told.
     *
     * @param request the token and key context
     * @return the attribute schema
     */
    List<BaseAttribute> cipherAttributes(KeyScopedRequestV2Dto request);

    /**
     * What generating random data needs to be told.
     *
     * @param request the token context
     * @return the attribute schema
     */
    List<BaseAttribute> randomAttributes(TokenProfileScopedRequestV2Dto request);

    /**
     * Signs the data the request carries.
     *
     * @param request the signing request
     * @return the signatures, correlated to the request items
     */
    SignDataResponseV2Dto signData(SignDataRequestV2Dto request);

    /**
     * Verifies the signatures the request carries.
     *
     * @param request the verification request
     * @return the verification results
     */
    VerifyDataResponseV2Dto verifyData(VerifyDataRequestV2Dto request);

    /**
     * Encrypts the data the request carries.
     *
     * @param request the encryption request
     * @return the encrypted data
     */
    EncryptDataResponseV2Dto encryptData(CipherDataRequestV2Dto request);

    /**
     * Decrypts the data the request carries.
     *
     * @param request the decryption request
     * @return the decrypted data
     */
    DecryptDataResponseV2Dto decryptData(CipherDataRequestV2Dto request);

    /**
     * Generates random data.
     *
     * @param request the random-data request
     * @return the random data
     */
    RandomDataResponseV2Dto randomData(RandomDataRequestV2Dto request);
}
