package com.otilm.cp.soft.service;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.cp.soft.model.TokenContext;
import com.otilm.cp.soft.model.TokenState;
import java.util.List;

/**
 * Turns the token attributes a V2 request carries into the token the provider works with.
 */
public interface TokenContextService {

    /**
     * Resolves the token the attributes address, creating it when they ask for a new one that does not exist yet.
     *
     * @param tokenAttributes the token attributes supplied with the request
     * @return the token and the code that opens its keystore
     */
    TokenContext resolve(List<RequestAttribute> tokenAttributes);

    /**
     * Reports whether the token the attributes address can be used, without creating or changing anything. This is what
     * a status request asks: it answers for a token that does not exist or cannot be opened rather than failing.
     *
     * @param tokenAttributes the token attributes supplied with the request
     * @return what inspecting the context found
     */
    TokenState inspect(List<RequestAttribute> tokenAttributes);
}
