package com.otilm.cp.soft.api.v2;

import com.otilm.api.interfaces.connector.cryptography.v2.CryptographicOperationsController;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.connector.common.v2.OperationExecutionMode;
import com.otilm.api.model.connector.cryptography.v2.KeyScopedRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.OperationTrackingRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.TokenProfileScopedRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.CipherDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.DecryptDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.EncryptDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.RandomDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.RandomDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.SignDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.SignDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.SignOperationStatusResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.VerifyDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.VerifyDataResponseV2Dto;
import com.otilm.cp.soft.exception.NotSupportedException;
import com.otilm.cp.soft.exception.OperationNotTrackedException;
import com.otilm.cp.soft.service.CryptographicOperationsV2Service;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

/**
 * Serves the V2 cryptographic operations.
 *
 * <p>
 * Signing, verifying, encrypting, decrypting and generating random data all complete inline, so signing accepts only
 * synchronous execution and nothing is ever tracked.
 * </p>
 */
@RestController
public class OperationsV2ControllerImpl implements CryptographicOperationsController {

    private static final String NOT_TRACKED = "This connector completes every operation inline and tracks none.";

    private CryptographicOperationsV2Service cryptographicOperationsV2Service;

    @Override
    public List<BaseAttribute> listEncryptAttributes(KeyScopedRequestV2Dto request) {
        return cryptographicOperationsV2Service.cipherAttributes(request);
    }

    @Override
    public EncryptDataResponseV2Dto encryptData(CipherDataRequestV2Dto request) {
        return cryptographicOperationsV2Service.encryptData(request);
    }

    @Override
    public List<BaseAttribute> listDecryptAttributes(KeyScopedRequestV2Dto request) {
        return cryptographicOperationsV2Service.cipherAttributes(request);
    }

    @Override
    public DecryptDataResponseV2Dto decryptData(CipherDataRequestV2Dto request) {
        return cryptographicOperationsV2Service.decryptData(request);
    }

    @Override
    public List<BaseAttribute> listSignAttributes(KeyScopedRequestV2Dto request) {
        return cryptographicOperationsV2Service.signatureAttributes(request);
    }

    @Override
    public ResponseEntity<SignDataResponseV2Dto> signData(SignDataRequestV2Dto request) {
        requireSynchronous(request);
        return ResponseEntity.ok(cryptographicOperationsV2Service.signData(request));
    }

    @Override
    public SignOperationStatusResponseV2Dto getSignStatus(OperationTrackingRequestV2Dto request) {
        throw new OperationNotTrackedException(NOT_TRACKED);
    }

    @Override
    public ResponseEntity<Void> cancelSign(OperationTrackingRequestV2Dto request) {
        throw new OperationNotTrackedException(NOT_TRACKED);
    }

    @Override
    public List<BaseAttribute> listVerifyAttributes(KeyScopedRequestV2Dto request) {
        return cryptographicOperationsV2Service.signatureAttributes(request);
    }

    @Override
    public VerifyDataResponseV2Dto verifyData(VerifyDataRequestV2Dto request) {
        return cryptographicOperationsV2Service.verifyData(request);
    }

    @Override
    public List<BaseAttribute> listRandomAttributes(TokenProfileScopedRequestV2Dto request) {
        return cryptographicOperationsV2Service.randomAttributes(request);
    }

    @Override
    public RandomDataResponseV2Dto randomData(RandomDataRequestV2Dto request) {
        return cryptographicOperationsV2Service.randomData(request);
    }

    private static void requireSynchronous(SignDataRequestV2Dto request) {
        if (request.getExecutionMode() != OperationExecutionMode.SYNCHRONOUS) {
            throw new NotSupportedException("Asynchronous execution is not supported.");
        }
    }

    @Autowired
    public void setCryptographicOperationsV2Service(CryptographicOperationsV2Service cryptographicOperationsV2Service) {
        this.cryptographicOperationsV2Service = cryptographicOperationsV2Service;
    }
}
