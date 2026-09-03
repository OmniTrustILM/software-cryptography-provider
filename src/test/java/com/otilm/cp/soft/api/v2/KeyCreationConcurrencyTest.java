package com.otilm.cp.soft.api.v2;

import com.otilm.api.model.connector.cryptography.v2.key.CreateKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairDataResponseV2Dto;
import com.otilm.cp.soft.exception.ConcurrentRequestException;
import com.otilm.cp.soft.testsupport.KeyRequestFixtures;
import com.otilm.cp.soft.testsupport.TokenContextFixtures;
import java.util.ArrayList;
import java.util.List;
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
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * The creation identifier promises one key per identifier however many times the request arrives, including when two
 * copies of it arrive at once. Only one can be recorded, and the other is told to repeat itself, which then answers
 * with the key the first one made.
 */
@SpringBootTest
class KeyCreationConcurrencyTest {

    private KeyV2ControllerImpl controller;

    @Autowired
    void setController(KeyV2ControllerImpl controller) {
        this.controller = controller;
    }

    @Test
    void twoCopiesOfOneCreationRequestProduceOneKey() throws Exception {
        // given
        CreateKeyRequestV2Dto request = KeyRequestFixtures
                .rsaKeyPair(TokenContextFixtures.uniqueName("v2-create-race"), "key-" + System.nanoTime());
        CyclicBarrier together = new CyclicBarrier(2);
        Callable<KeyPairDataResponseV2Dto> create = () -> {
            together.await();
            return (KeyPairDataResponseV2Dto) controller.createKey(request).getBody();
        };

        // when
        List<Future<KeyPairDataResponseV2Dto>> answers;
        try (ExecutorService threads = Executors.newFixedThreadPool(2)) {
            answers = threads.invokeAll(List.of(create, create));
        }

        // then
        List<String> created = new ArrayList<>();
        for (Future<KeyPairDataResponseV2Dto> answer : answers) {
            try {
                created.add(answer.get().getPrivateKeyData().getKeyMeta().toString());
            } catch (ExecutionException e) {
                assertInstanceOf(ConcurrentRequestException.class, e.getCause(),
                        () -> "a request that lost the race must be told to repeat itself, not fail: " + e.getCause());
            }
        }
        assertFalse(created.isEmpty(), "one of the two requests must have created the key");
        assertEquals(1, created.stream().distinct().count(), "one creation identifier means one key");

        // and repeating the request is answered with that same key rather than making another
        KeyPairDataResponseV2Dto repeat = (KeyPairDataResponseV2Dto) controller.createKey(request).getBody();
        assertNotNull(repeat);
        assertEquals(created.get(0), repeat.getPrivateKeyData().getKeyMeta().toString());
    }
}
