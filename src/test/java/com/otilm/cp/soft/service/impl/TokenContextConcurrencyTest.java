package com.otilm.cp.soft.service.impl;

import com.otilm.cp.soft.exception.ConcurrentRequestException;
import com.otilm.cp.soft.model.TokenContext;
import com.otilm.cp.soft.service.TokenContextService;
import com.otilm.cp.soft.testsupport.TokenContextFixtures;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

/**
 * A token comes into existence the first time a context names it, so two requests naming the same new token can arrive
 * before either has created it. Only one row can carry the name, and the other request is told to repeat itself rather
 * than being failed outright or given a second token wearing the same name.
 */
@SpringBootTest
class TokenContextConcurrencyTest {

    private static final String CODE = "00000000";

    private TokenContextService tokenContextService;

    @Autowired
    void setTokenContextService(TokenContextService tokenContextService) {
        this.tokenContextService = tokenContextService;
    }

    @Test
    void twoRequestsNamingTheSameNewTokenEndUpOnOneToken() throws Exception {
        // given
        String name = "v2-race-" + UUID.randomUUID();
        CyclicBarrier together = new CyclicBarrier(2);
        Callable<TokenContext> resolve = () -> {
            together.await();
            return tokenContextService.resolve(TokenContextFixtures.newToken(name, CODE));
        };

        // when
        List<Future<TokenContext>> answers;
        try (ExecutorService threads = Executors.newFixedThreadPool(2)) {
            answers = threads.invokeAll(List.of(resolve, resolve));
        }

        // then
        List<UUID> resolved = new ArrayList<>();
        for (Future<TokenContext> answer : answers) {
            try {
                resolved.add(answer.get().instance().getUuid());
            } catch (ExecutionException e) {
                assertInstanceOf(ConcurrentRequestException.class, e.getCause(),
                        () -> "a request that lost the race must be told to repeat itself, not fail: " + e.getCause());
            }
        }
        assertFalse(resolved.isEmpty(), "one of the two requests must have created the token");
        assertEquals(1, resolved.stream().distinct().count(), "only one token can carry the name");

        // and a request that lost the race reaches that same token by repeating itself
        assertEquals(resolved.get(0),
                tokenContextService.resolve(TokenContextFixtures.newToken(name, CODE)).instance().getUuid());
    }
}
