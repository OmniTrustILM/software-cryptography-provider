package com.otilm.cp.soft.service.impl;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.v2.content.SecretAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.otilm.cp.soft.attribute.TokenInstanceAttributes;
import com.otilm.cp.soft.dao.entity.TokenInstance;
import com.otilm.cp.soft.dao.repository.TokenInstanceRepository;
import com.otilm.cp.soft.exception.ConcurrentRequestException;
import com.otilm.cp.soft.exception.ResourceMissingException;
import com.otilm.cp.soft.exception.TokenInstanceException;
import com.otilm.cp.soft.model.TokenAvailability;
import com.otilm.cp.soft.model.TokenContext;
import com.otilm.cp.soft.model.TokenState;
import com.otilm.cp.soft.service.TokenContextService;
import com.otilm.cp.soft.util.KeyStoreUtil;
import com.otilm.cp.soft.util.TokenMetadataUtil;
import jakarta.transaction.Transactional;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;

/**
 * Resolves the token a V2 request addressed through its attributes.
 *
 * <p>
 * The V2 interfaces have no operation that creates a token, so a context asking for a new one brings it into existence
 * the first time it is used and finds the same token on every request after that. A context selecting an existing token
 * only ever finds one.
 * </p>
 *
 * <p>
 * Whichever way the token was addressed, the code it carries is checked by opening the keystore before the context is
 * handed out: everything downstream needs the keystore, so a code that does not open it is a failure of the request
 * rather than of the operation it was going to perform.
 * </p>
 */
@Service
@Transactional
public class TokenContextServiceImpl implements TokenContextService {

    private static final Logger logger = LoggerFactory.getLogger(TokenContextServiceImpl.class);

    private static final String ACTION_NEW = "new";

    private static final String ACTION_EXISTING = "existing";

    private static final String KEYSTORE_TYPE = "PKCS12";

    private TokenInstanceRepository tokenInstanceRepository;

    @Override
    public TokenContext resolve(List<RequestAttribute> tokenAttributes) {
        String action = addressing(tokenAttributes);
        String code = requiredCode(tokenAttributes);

        TokenInstance instance = locate(action, tokenAttributes)
                .orElseGet(() -> createWhenNew(action, tokenAttributes, code));

        requireCodeOpensKeystore(instance, code);
        rememberCode(instance, code);
        return new TokenContext(instance, code);
    }

    @Override
    public TokenState inspect(List<RequestAttribute> tokenAttributes) {
        Optional<TokenInstance> instance;
        String code;
        try {
            code = requiredCode(tokenAttributes);
            instance = locate(addressing(tokenAttributes), tokenAttributes);
        } catch (TokenInstanceException e) {
            logger.debug("A token status request carried a context that addresses no token", e);
            return new TokenState(TokenAvailability.UNUSABLE, e.getMessage());
        }

        if (instance.isEmpty()) {
            return new TokenState(TokenAvailability.MISSING, "No token answers to the supplied context");
        }
        try {
            requireCodeOpensKeystore(instance.get(), code);
        } catch (TokenInstanceException e) {
            return new TokenState(TokenAvailability.UNUSABLE, e.getMessage());
        }
        return new TokenState(TokenAvailability.AVAILABLE, null);
    }

    /**
     * Keeps the stored code in step with the one the context proved. The V2 interfaces have no activation step, so a
     * request carrying a code that opens the keystore is what makes the token usable; the operations the provider
     * performs read the stored code, and a token addressed only through V2 would otherwise have none.
     */
    private static void rememberCode(TokenInstance instance, String code) {
        if (!code.equals(instance.getCode())) {
            instance.setCode(code);
        }
    }

    /** Finds the token the context addresses. Nothing is created here, so a status request changes nothing. */
    private Optional<TokenInstance> locate(String action, List<RequestAttribute> tokenAttributes) {
        return switch (action) {
            case ACTION_NEW -> tokenInstanceRepository.findByName(tokenName(tokenAttributes));
            case ACTION_EXISTING -> tokenInstanceRepository.findByUuid(selectedToken(tokenAttributes));
            default -> throw new TokenInstanceException("Unknown way to address a token: " + action);
        };
    }

    /**
     * Creates the token a context asked for by name, which is how a token comes into existence under interfaces that
     * have no operation for it. A context that selected an existing token is asking for one that is gone, which is a
     * missing object rather than a context this connector cannot read.
     */
    private TokenInstance createWhenNew(String action, List<RequestAttribute> tokenAttributes, String code) {
        if (!ACTION_NEW.equals(action)) {
            throw new ResourceMissingException("The selected token does not exist");
        }

        String name = tokenName(tokenAttributes);
        logger.debug("Creating token instance {} for a v2 request that addressed it", name);

        TokenInstance instance = new TokenInstance();
        instance.setUuid(UUID.randomUUID().toString());
        instance.setName(name);
        instance.setCode(code);
        instance.setData(KeyStoreUtil.createNewKeystore(KEYSTORE_TYPE, code));
        instance.setMetadata(List.<MetadataAttribute>of(TokenMetadataUtil.nameMetadata(name)));

        try {
            return tokenInstanceRepository.saveAndFlush(instance);
        } catch (DataIntegrityViolationException e) {
            // The name is the only thing unique about this row, so another request addressing the same token got there
            // first. Its keystore is the one to use, and the caller reaches it by repeating the request.
            throw new ConcurrentRequestException("Token " + name + " is being created by another request", e);
        }
    }

    private static void requireCodeOpensKeystore(TokenInstance instance, String code) {
        try {
            KeyStoreUtil.loadKeystore(instance.getData(), code);
        } catch (IllegalStateException e) {
            logger.debug("The supplied code does not open token {}", instance.getName(), e);
            throw new TokenInstanceException("The supplied code does not open token " + instance.getName());
        }
    }

    private static String addressing(List<RequestAttribute> tokenAttributes) {
        return requiredString(TokenInstanceAttributes.ATTRIBUTE_DATA_CREATE_TOKEN_ACTION, tokenAttributes,
                "The token context does not say how the token is addressed");
    }

    private static String tokenName(List<RequestAttribute> tokenAttributes) {
        return requiredString(TokenInstanceAttributes.ATTRIBUTE_DATA_NEW_TOKEN_NAME, tokenAttributes,
                "The token context does not name the token to use");
    }

    private static UUID selectedToken(List<RequestAttribute> tokenAttributes) {
        String selected = requiredString(TokenInstanceAttributes.ATTRIBUTE_DATA_SELECT_EXISTING_TOKEN, tokenAttributes,
                "The token context does not select a token");
        try {
            return UUID.fromString(selected);
        } catch (IllegalArgumentException e) {
            throw new TokenInstanceException("The selected token is not identified by a UUID");
        }
    }

    private static String requiredString(String attributeName, List<RequestAttribute> tokenAttributes,
            String whenMissing) {
        StringAttributeContentV2 content = AttributeDefinitionUtils
                .getSingleItemAttributeContentValue(attributeName, tokenAttributes, StringAttributeContentV2.class);
        if (content == null || content.getData() == null) {
            throw new TokenInstanceException(whenMissing);
        }
        return content.getData();
    }

    private static String requiredCode(List<RequestAttribute> tokenAttributes) {
        SecretAttributeContentV2 content = AttributeDefinitionUtils
                .getSingleItemAttributeContentValue(TokenInstanceAttributes.ATTRIBUTE_DATA_TOKEN_CODE, tokenAttributes,
                        SecretAttributeContentV2.class);
        if (content == null || content.getData() == null || content.getData().getSecret() == null) {
            throw new TokenInstanceException("The token context does not carry the code that opens the token");
        }
        return content.getData().getSecret();
    }

    @Autowired
    public void setTokenInstanceRepository(TokenInstanceRepository tokenInstanceRepository) {
        this.tokenInstanceRepository = tokenInstanceRepository;
    }
}
