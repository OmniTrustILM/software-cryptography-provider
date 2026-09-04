package com.otilm.cp.soft.api.v2;

import com.otilm.api.interfaces.connector.cryptography.v2.KeyController;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.connector.cryptography.v2.KeyScopedRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.OperationTrackingRequestV2Dto;
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
import com.otilm.api.model.connector.cryptography.v2.key.KeyCreationResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyCreationStatusResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyDestructionStatusResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyOperationResponseV2Dto;
import com.otilm.cp.soft.exception.NotSupportedException;
import com.otilm.cp.soft.exception.OperationNotTrackedException;
import com.otilm.cp.soft.service.CryptographicKeyV2Service;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

/**
 * Serves the V2 key operations.
 *
 * <p>
 * Every operation completes inline, so nothing is ever tracked: the status and cancellation operations answer as the
 * contract states for an operation the connector does not track. Key import and export are not offered yet, so this
 * connector declares neither feature and the key types it would move are empty.
 * </p>
 */
@RestController
public class KeyV2ControllerImpl implements KeyController {

    private static final String NO_KEY_TRANSFER = "Key import and export are not supported.";

    private static final String NOT_TRACKED = "This connector completes every operation inline and tracks none.";

    private CryptographicKeyV2Service cryptographicKeyV2Service;

    @Override
    public List<BaseAttribute> listCreateKeyAttributes(CreateKeyAttributesRequestV2Dto request) {
        return cryptographicKeyV2Service.createKeyAttributes(request);
    }

    @Override
    public ResponseEntity<KeyCreationResponseV2Dto> createKey(CreateKeyRequestV2Dto request) {
        return ResponseEntity.ok(cryptographicKeyV2Service.createKey(request));
    }

    @Override
    public KeyCreationStatusResponseV2Dto getCreateKeyStatus(OperationTrackingRequestV2Dto request) {
        throw new OperationNotTrackedException(NOT_TRACKED);
    }

    @Override
    public ResponseEntity<Void> cancelCreateKey(OperationTrackingRequestV2Dto request) {
        throw new OperationNotTrackedException(NOT_TRACKED);
    }

    @Override
    public ResponseEntity<KeyOperationResponseV2Dto> destroyKey(DestroyKeyRequestV2Dto request) {
        cryptographicKeyV2Service.destroyKey(request);
        return ResponseEntity.ok(new KeyOperationResponseV2Dto());
    }

    @Override
    public KeyDestructionStatusResponseV2Dto getDestroyKeyStatus(OperationTrackingRequestV2Dto request) {
        throw new OperationNotTrackedException(NOT_TRACKED);
    }

    @Override
    public ResponseEntity<Void> cancelDestroyKey(OperationTrackingRequestV2Dto request) {
        throw new OperationNotTrackedException(NOT_TRACKED);
    }

    @Override
    public List<ImportableKeyTypeV2Dto> listImportableKeyTypes(TokenProfileScopedRequestV2Dto request) {
        return cryptographicKeyV2Service.importableKeyTypes(request);
    }

    @Override
    public List<BaseAttribute> listImportKeyAttributes(ImportKeyAttributesRequestV2Dto request) {
        return cryptographicKeyV2Service.importKeyAttributes(request);
    }

    @Override
    public ResponseEntity<KeyCreationResponseV2Dto> importKey(ImportKeyRequestV2Dto request) {
        return ResponseEntity.ok(cryptographicKeyV2Service.importKey(request));
    }

    /** An import completes inline, so there is never one in flight to report on. */
    @Override
    public KeyCreationStatusResponseV2Dto getImportKeyStatus(OperationTrackingRequestV2Dto request) {
        throw new OperationNotTrackedException(NOT_TRACKED);
    }

    @Override
    public ResponseEntity<Void> cancelImportKey(OperationTrackingRequestV2Dto request) {
        throw new OperationNotTrackedException(NOT_TRACKED);
    }

    /**
     * What became of an import. Unlike the status of one in flight, this answers a caller that lost the response to an
     * import that did happen, which is what the identifier it was asked under is for.
     */
    @Override
    public KeyCreationStatusResponseV2Dto getImportKeyResult(ImportKeyResultRequestV2Dto request) {
        return cryptographicKeyV2Service.importResult(request);
    }

    @Override
    public List<ExportableKeyTypeV2Dto> listExportableKeyTypes(TokenProfileScopedRequestV2Dto request) {
        return List.of();
    }

    @Override
    public List<BaseAttribute> listExportKeyAttributes(KeyScopedRequestV2Dto request) {
        throw new NotSupportedException(NO_KEY_TRANSFER);
    }

    @Override
    public ExportKeyResponseV2Dto exportKey(ExportKeyRequestV2Dto request) {
        throw new NotSupportedException(NO_KEY_TRANSFER);
    }

    @Autowired
    public void setCryptographicKeyV2Service(CryptographicKeyV2Service cryptographicKeyV2Service) {
        this.cryptographicKeyV2Service = cryptographicKeyV2Service;
    }
}
