package com.otilm.cp.soft.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.cp.soft.attribute.TokenInstanceAttributes;
import com.otilm.cp.soft.dao.entity.TokenInstance;
import com.otilm.cp.soft.dao.repository.TokenInstanceRepository;
import com.otilm.cp.soft.exception.ConcurrentRequestException;
import com.otilm.cp.soft.exception.ResourceMissingException;
import com.otilm.cp.soft.exception.TokenInstanceException;
import com.otilm.cp.soft.model.TokenAvailability;
import com.otilm.cp.soft.model.TokenContext;
import com.otilm.cp.soft.model.TokenState;
import com.otilm.cp.soft.service.KeyStoreCacheService;
import com.otilm.cp.soft.service.TokenContextService;
import com.otilm.cp.soft.util.AttributeValue;
import com.otilm.cp.soft.util.KeyStoreUtil;
import com.otilm.cp.soft.util.TokenMetadataUtil;
import jakarta.transaction.Transactional;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
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

    private KeyStoreCacheService keyStoreCacheService;

    private TokenInstanceRepository tokenInstanceRepository;

    @Override
    public TokenContext resolve(List<RequestAttribute> tokenAttributes) {
        String action = addressing(tokenAttributes);
        String code = requiredCode(tokenAttributes);

        Optional<TokenInstance> found = locate(action, tokenAttributes);
        if (found.isEmpty()) {
            // A token brought into existence here was made with this code, so there is nothing to check against it
            // and nothing to write down.
            return new TokenContext(createWhenNew(action, tokenAttributes), code);
        }

        TokenInstance instance = found.get();
        rememberCode(instance, code, requireCodeOpensToken(instance, code));
        return new TokenContext(instance, code);
    }

    @Override
    public Optional<TokenContext> locate(List<RequestAttribute> tokenAttributes) {
        String action = addressing(tokenAttributes);
        String code = requiredCode(tokenAttributes);

        Optional<TokenInstance> instance = locate(action, tokenAttributes);
        if (instance.isEmpty()) {
            requireTokenMayStillBeCreated(action);
            return Optional.empty();
        }
        requireCodeOpensToken(instance.get(), code);
        return Optional.of(new TokenContext(instance.get(), code));
    }

    /**
     * A context selecting an existing token that is not there addresses nothing, whether or not the call would have
     * created one. A context asking for a token by name is asking for one that this connector would create when it came
     * to be used, so nothing is wrong with it yet.
     */
    private static void requireTokenMayStillBeCreated(String action) {
        if (!ACTION_NEW.equals(action)) {
            throw new ResourceMissingException("The selected token does not exist");
        }
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
            requireCodeOpensToken(instance.get(), code);
        } catch (TokenInstanceException e) {
            return new TokenState(TokenAvailability.UNUSABLE, e.getMessage());
        }
        return new TokenState(TokenAvailability.AVAILABLE, null);
    }

    /**
     * Keeps the stored code in step with the one the context proved. The V2 interfaces have no activation step, so a
     * request carrying a code that opens the keystore is what makes the token usable; the operations the provider
     * performs read the stored code, and a token addressed only through V2 would otherwise have none.
     *
     * <p>
     * A token that already had a code stored has just been held to it, so there is nothing to write; only one that had
     * none — deactivated through the V1 interfaces — is written to, and what was cached for it went when it was
     * deactivated.
     * </p>
     */
    private void rememberCode(TokenInstance instance, String code, String stored) {
        if (stored == null) {
            instance.setCode(code);
            keyStoreCacheService.evictAfterCommit(instance.getUuid());
        }
    }

    /** Finds the token the context addresses. Nothing is created here, so a request that only reads changes nothing. */
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
    private TokenInstance createWhenNew(String action, List<RequestAttribute> tokenAttributes) {
        if (!ACTION_NEW.equals(action)) {
            throw new ResourceMissingException("The selected token does not exist");
        }

        // Read here rather than taken from the caller: a keystore cannot be made without a code, so the method that
        // makes one is the method that requires it.
        String code = requiredCode(tokenAttributes);
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

    /**
     * Refuses a context whose code does not open the token, and answers with the code the token had stored.
     *
     * <p>
     * A keystore has one code, and the one stored beside it is known to open it: it made the keystore, or it was
     * written down only after it had opened it. So a code that differs from the stored one does not open the keystore,
     * and comparing them settles it without opening anything. Both are otherwise as costly as each other — what is
     * stored is itself protected under a key derived from a passphrase — so the comparison is made against the code
     * kept beside the token's cached material, which the operations this provider performs load anyway.
     * </p>
     *
     * <p>
     * A token with no code stored has none to compare against, so that one is opened. It is how a token deactivated
     * through the V1 interfaces comes back into use.
     * </p>
     *
     * @return the code the token had stored, or {@code null} where it had none
     */
    private String requireCodeOpensToken(TokenInstance instance, String code) {
        if (instance.hasCode()) {
            String stored = storedCodeOf(instance);
            if (!isTheSameCode(stored, code)) {
                logger.debug("The supplied code is not the one stored for token {}", instance.getName());
                throw new TokenInstanceException("The supplied code does not open token " + instance.getName());
            }
            return stored;
        }
        try {
            KeyStoreUtil.loadKeystore(instance.getData(), code);
        } catch (IllegalStateException e) {
            logger.debug("The supplied code does not open token {}", instance.getName(), e);
            throw new TokenInstanceException("The supplied code does not open token " + instance.getName());
        }
        return null;
    }

    /**
     * The code the token has stored, taken from what was cached for it. A token whose material cannot be read is a
     * token nothing can be done with, which is the same answer a code that does not open it gets.
     */
    private String storedCodeOf(TokenInstance instance) {
        try {
            return keyStoreCacheService.loadKeyMaterial(instance.getUuid()).openedWith();
        } catch (NotFoundException | IllegalStateException e) {
            logger.debug("The code stored for token {} could not be read back", instance.getName(), e);
            throw new TokenInstanceException("Token " + instance.getName() + " cannot be opened");
        }
    }

    /** Compared without letting how long it took say how much of it was right. */
    private static boolean isTheSameCode(String stored, String supplied) {
        return MessageDigest
                .isEqual(stored.getBytes(StandardCharsets.UTF_8), supplied.getBytes(StandardCharsets.UTF_8));
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
        String stated = AttributeValue.string(attributeName, tokenAttributes);
        if (stated == null) {
            throw new TokenInstanceException(whenMissing);
        }
        return stated;
    }

    private static String requiredCode(List<RequestAttribute> tokenAttributes) {
        String code = AttributeValue.secret(TokenInstanceAttributes.ATTRIBUTE_DATA_TOKEN_CODE, tokenAttributes);
        if (code == null) {
            throw new TokenInstanceException("The token context does not carry the code that opens the token");
        }
        return code;
    }

    @Autowired
    public void setKeyStoreCacheService(KeyStoreCacheService keyStoreCacheService) {
        this.keyStoreCacheService = keyStoreCacheService;
    }

    @Autowired
    public void setTokenInstanceRepository(TokenInstanceRepository tokenInstanceRepository) {
        this.tokenInstanceRepository = tokenInstanceRepository;
    }
}
