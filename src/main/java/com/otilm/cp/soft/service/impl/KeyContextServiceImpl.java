package com.otilm.cp.soft.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.otilm.cp.soft.attribute.KeyAttributes;
import com.otilm.cp.soft.dao.entity.KeyData;
import com.otilm.cp.soft.dao.repository.KeyDataRepository;
import com.otilm.cp.soft.exception.KeyManagementException;
import com.otilm.cp.soft.exception.ResourceMissingException;
import com.otilm.cp.soft.model.CachedKeyData;
import com.otilm.cp.soft.model.CachedKeyMaterial;
import com.otilm.cp.soft.model.KeyContext;
import com.otilm.cp.soft.model.OpenedToken;
import com.otilm.cp.soft.model.OperationKey;
import com.otilm.cp.soft.model.TokenContext;
import com.otilm.cp.soft.service.KeyContextService;
import com.otilm.cp.soft.service.KeyDataCacheService;
import com.otilm.cp.soft.service.KeyStoreCacheService;
import com.otilm.cp.soft.service.TokenContextService;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Resolves the key a V2 request addressed through the metadata this connector published for it.
 *
 * <p>
 * A key is addressed by its durable reference rather than by its alias, because the two halves of a key pair share an
 * alias and an operation applies to one of them. The key must belong to the token the same request addressed: metadata
 * naming a key in another token addresses nothing here.
 * </p>
 *
 * <p>
 * Metadata that carries no reference is a request this connector cannot read, while a reference to a key that is not
 * here is a request for something absent. The two are answered differently, so a caller can tell a mistake in what it
 * sent from a key that has since been destroyed.
 * </p>
 */
@Service
@Transactional
public class KeyContextServiceImpl implements KeyContextService {

    private KeyDataRepository keyDataRepository;

    private TokenContextService tokenContextService;

    private KeyDataCacheService keyDataCacheService;

    private KeyStoreCacheService keyStoreCacheService;

    private TransactionTemplate resolutionTransaction;

    @Override
    public KeyContext resolve(List<RequestAttribute> tokenAttributes, List<MetadataAttribute> keyMeta) {
        TokenContext token = tokenContextService.resolve(tokenAttributes);
        UUID reference = reference(keyMeta);

        KeyData key = keyDataRepository
                .findByUuid(reference)
                .orElseThrow(() -> new ResourceMissingException("The addressed key does not exist"));
        if (!token.instance().getUuid().equals(key.getTokenInstanceUuid())) {
            throw new ResourceMissingException("The addressed key does not belong to the addressed token");
        }
        return new KeyContext(token, key);
    }

    @Override
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public OperationKey resolveForOperation(List<RequestAttribute> tokenAttributes, List<MetadataAttribute> keyMeta) {
        return tokenContextService
                .open(tokenAttributes)
                .map(token -> operationKeyOf(token, keyMeta))
                .orElseGet(() -> resolvedInTransaction(tokenAttributes, keyMeta));
    }

    @Override
    public List<MetadataAttribute> publishPair(KeyData key) {
        return List.of(KeyAttributes.buildAliasMetadata(key.getName()));
    }

    @Override
    public List<MetadataAttribute> publish(KeyData key) {
        List<MetadataAttribute> metadata = new ArrayList<>(publishPair(key));
        metadata.add(KeyAttributes.buildKeyReferenceMetadata(key.getUuid().toString()));
        return metadata;
    }

    /**
     * Resolving a token can create it or store its code. Both roll back with a key read that fails.
     */
    private OperationKey resolvedInTransaction(List<RequestAttribute> tokenAttributes,
            List<MetadataAttribute> keyMeta) {
        return resolutionTransaction
                .execute(status -> operationKeyOf(opened(tokenContextService.resolve(tokenAttributes)), keyMeta));
    }

    private OperationKey operationKeyOf(OpenedToken token, List<MetadataAttribute> keyMeta) {
        CachedKeyData key = cachedKey(reference(keyMeta), token.material());
        if (!token.uuid().equals(key.tokenInstanceUuid())) {
            throw new ResourceMissingException("The addressed key does not belong to the addressed token");
        }
        return new OperationKey(key, token.material());
    }

    private OpenedToken opened(TokenContext token) {
        UUID uuid = token.instance().getUuid();
        try {
            return new OpenedToken(uuid, keyStoreCacheService.loadKeyMaterial(uuid));
        } catch (NotFoundException e) {
            throw new ResourceMissingException("The selected token does not exist", e);
        }
    }

    private CachedKeyData cachedKey(UUID reference, CachedKeyMaterial material) {
        try {
            return keyDataCacheService.getCachedKeyData(reference, material);
        } catch (NotFoundException e) {
            throw new ResourceMissingException("The addressed key does not exist", e);
        }
    }

    private static UUID reference(List<MetadataAttribute> keyMeta) {
        StringAttributeContentV2 content = AttributeDefinitionUtils
                .getSingleItemAttributeContentValue(KeyAttributes.ATTRIBUTE_META_KEY_REFERENCE, keyMeta,
                        StringAttributeContentV2.class);
        if (content == null || content.getData() == null) {
            throw new KeyManagementException("The key metadata does not carry the key reference");
        }
        try {
            return UUID.fromString(content.getData());
        } catch (IllegalArgumentException e) {
            throw new KeyManagementException("The key reference is not a reference this provider issued");
        }
    }

    @Autowired
    public void setKeyDataRepository(KeyDataRepository keyDataRepository) {
        this.keyDataRepository = keyDataRepository;
    }

    @Autowired
    public void setTokenContextService(TokenContextService tokenContextService) {
        this.tokenContextService = tokenContextService;
    }

    @Autowired
    public void setKeyDataCacheService(KeyDataCacheService keyDataCacheService) {
        this.keyDataCacheService = keyDataCacheService;
    }

    @Autowired
    public void setKeyStoreCacheService(KeyStoreCacheService keyStoreCacheService) {
        this.keyStoreCacheService = keyStoreCacheService;
    }

    @Autowired
    public void setTransactionManager(PlatformTransactionManager transactionManager) {
        this.resolutionTransaction = new TransactionTemplate(transactionManager);
    }
}
