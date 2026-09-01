package com.otilm.cp.soft.model;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Regression guard for the thread-safety claim in {@link CachedKeyMaterial} which states that the BouncyCastle
 * {@link PrivateKey} implementations stored in the record ({@code BCRSAPrivateCrtKey}, {@code BCECPrivateKey},
 * {@code BCFalconPrivateKey}, {@code BCMLDSAPrivateKey}, {@code BCSLHDSAPrivateKey}) are
 * immutable and therefore safe for concurrent reads without synchronization.
 *
 * <p><b>Design:</b>
 * <ul>
 *   <li>A pool of {@value #N_COLD_KEYS} fresh key pairs is pre-generated per algorithm so that each round races
 *   on a key whose potential lazy state has <em>never</em> been touched by a prior {@code initSign} call.</li>
 *   <li>{@value #THREAD_COUNT} virtual threads each create their own {@link Signature} instance (which is not thread-safe)
 *   and synchronize on a {@link java.util.concurrent.CyclicBarrier} placed immediately before {@link Signature#initSign}
 *   so that all first-touches of the shared key object happen at the same instant.</li>
 *   <li>Every signature produced by every thread is verified with the corresponding public key.</li>
 *   <li>The key is always fetched through {@link CachedKeyMaterial#privateKeys()} to exercise the actual production code path.</li>
 * </ul>
 */
class CachedKeyMaterialConcurrencyTest {

    /**
     * Number of threads racing simultaneously on each shared key instance.
     */
    private static final int THREAD_COUNT = 16;

    /**
     * Number of fresh key pairs per algorithm. Each round uses a distinct key pair so that the
     * first-touch race is repeated with a key that has never had {@code initSign} called on it.
     */
    private static final int N_COLD_KEYS = 8;

    /**
     * Fewer rounds for SLH-DSA because signing is more expensive for that algorithm family.
     */
    private static final int N_COLD_KEYS_SLHDSA = 3;

    private static final byte[] DATA = "Regression probe — CachedKeyMaterial thread-safety".getBytes(StandardCharsets.UTF_8);

    private static final List<KeyPair> RSA_POOL;
    private static final List<KeyPair> EC_POOL;
    private static final List<KeyPair> FALCON_POOL;
    private static final List<KeyPair> MLDSA_POOL;
    private static final List<KeyPair> SLHDSA_POOL;

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        try {
            KeyPairGenerator kpg;

            kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
            kpg.initialize(2048);
            RSA_POOL = generateKeyPairs(kpg, N_COLD_KEYS);

            kpg = KeyPairGenerator.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            EC_POOL = generateKeyPairs(kpg, N_COLD_KEYS);

            kpg = KeyPairGenerator.getInstance("Falcon", BouncyCastlePQCProvider.PROVIDER_NAME);
            kpg.initialize(FalconParameterSpec.falcon_512);
            FALCON_POOL = generateKeyPairs(kpg, N_COLD_KEYS);

            kpg = KeyPairGenerator.getInstance("ML-DSA", BouncyCastleProvider.PROVIDER_NAME);
            kpg.initialize(MLDSAParameterSpec.fromName("ML-DSA-44"));
            MLDSA_POOL = generateKeyPairs(kpg, N_COLD_KEYS);

            kpg = KeyPairGenerator.getInstance("SLH-DSA", BouncyCastleProvider.PROVIDER_NAME);
            kpg.initialize(SLHDSAParameterSpec.fromName("SLH-DSA-SHA2-128f"));
            SLHDSA_POOL = generateKeyPairs(kpg, N_COLD_KEYS_SLHDSA);

        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private static List<KeyPair> generateKeyPairs(KeyPairGenerator kpg, int count) {
        List<KeyPair> pool = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            pool.add(kpg.generateKeyPair());
        }
        return Collections.unmodifiableList(pool);
    }

    static Stream<Arguments> keyFixtures() {
        return Stream.of(
                Arguments.of("BCRSAPrivateCrtKey (RSA-2048)",
                        RSA_POOL, "SHA256withRSA", BouncyCastleProvider.PROVIDER_NAME),
                Arguments.of("BCECPrivateKey (ECDSA secp256r1)",
                        EC_POOL, "SHA256withECDSA", BouncyCastleProvider.PROVIDER_NAME),
                Arguments.of("BCFalconPrivateKey (Falcon-512)",
                        FALCON_POOL, "FALCON", BouncyCastlePQCProvider.PROVIDER_NAME),
                Arguments.of("BCMLDSAPrivateKey (ML-DSA-44)",
                        MLDSA_POOL, "ML-DSA", BouncyCastleProvider.PROVIDER_NAME),
                Arguments.of("BCSLHDSAPrivateKey (SLH-DSA-SHA2-128f)",
                        SLHDSA_POOL, "SLH-DSA", BouncyCastleProvider.PROVIDER_NAME)
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("keyFixtures")
    void concurrentInitSign_sharedKeyRemainsIncorruptible(String label,
                                                          List<KeyPair> keyPool,
                                                          String algorithm,
                                                          String provider) throws Exception {

        for (KeyPair freshPair : keyPool) {
            // The CachedKeyMaterial wrapping a cold key pair — this is the object every thread reads from.
            CachedKeyMaterial material = new CachedKeyMaterial(
                    Collections.singletonMap("key", freshPair.getPrivate()),
                    Collections.singletonMap("key", freshPair.getPublic()));

            // Barrier placed *before* initSign so all threads touch the shared key at the same instant.
            java.util.concurrent.CyclicBarrier startGate =
                    new java.util.concurrent.CyclicBarrier(THREAD_COUNT);

            List<Throwable> errors = Collections.synchronizedList(new ArrayList<>());
            byte[][] signatures = new byte[THREAD_COUNT][];

            List<Thread> threads = new ArrayList<>(THREAD_COUNT);
            for (int t = 0; t < THREAD_COUNT; t++) {
                final int idx = t;
                threads.add(Thread.ofVirtual().start(() -> {
                    try {
                        // Signature is NOT thread-safe — each thread owns its own instance.
                        // Create it before the barrier so setup cost is not inside the race window.
                        Signature sig = Signature.getInstance(algorithm, provider);
                        startGate.await(); // synchronize: all threads hit initSign at once
                        sig.initSign(material.privateKeys().get("key"));
                        sig.update(DATA);
                        signatures[idx] = sig.sign();
                    } catch (Throwable e) {
                        errors.add(e);
                    }
                }));
            }

            for (Thread t : threads) {
                t.join();
            }

            if (!errors.isEmpty()) {
                AssertionError failure = new AssertionError(
                        "Concurrent Signature.initSign raised " + errors.size()
                                + " exception(s) for " + label + ". The BC key class likely has mutable "
                                + "lazy-cached state — re-evaluate the thread-safety claim in CachedKeyMaterial.");
                errors.forEach(failure::addSuppressed);
                throw failure;
            }

            // Every thread must have produced a verifiably correct signature.
            // Checking only the final iteration would miss transient corruption.
            for (int t = 0; t < THREAD_COUNT; t++) {
                assertNotNull(signatures[t],
                        "Thread " + t + " produced a null signature for " + label);
                Signature verifier = Signature.getInstance(algorithm, provider);
                verifier.initVerify(freshPair.getPublic());
                verifier.update(DATA);
                assertTrue(verifier.verify(signatures[t]),
                        "Thread " + t + " produced an invalid signature for " + label
                                + " — possible silent state corruption in the shared key instance");
            }
        }
    }
}
