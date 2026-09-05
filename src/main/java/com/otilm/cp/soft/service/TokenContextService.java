package com.otilm.cp.soft.service;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.cp.soft.model.TokenContext;
import com.otilm.cp.soft.model.TokenState;
import java.util.List;
import java.util.Optional;

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
     * Finds the token the attributes address, without bringing one into existence.
     *
     * <p>
     * A call that only describes what this connector accepts, or reports on what it already did, must leave nothing
     * behind: asking which key types can be imported is not asking for a token. The context is still read and refused
     * where it cannot be acted on, and the code it carries is still checked against a token that exists.
     * </p>
     *
     * @param tokenAttributes the token attributes supplied with the request
     * @return the token and the code that opens it, or empty where no token answers to the context yet
     */
    Optional<TokenContext> locate(List<RequestAttribute> tokenAttributes);

    /**
     * Reports whether the token the attributes address can be used, without creating or changing anything. This is what
     * a status request asks: it answers for a token that does not exist or cannot be opened rather than failing.
     *
     * @param tokenAttributes the token attributes supplied with the request
     * @return what inspecting the context found
     */
    TokenState inspect(List<RequestAttribute> tokenAttributes);
}
