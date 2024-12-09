package com.czertainly.csc.signing.configuration;

import com.czertainly.csc.configuration.keypools.KeyPoolProfile;
import com.czertainly.csc.configuration.keypools.KeyUsageDesignation;
import com.czertainly.csc.model.signserver.CryptoToken;
import com.czertainly.csc.signing.filter.ConformanceLevelCriterion;
import com.czertainly.csc.signing.filter.Worker;
import com.czertainly.csc.utils.configuration.KeyPoolProfileBuilder;
import com.czertainly.csc.utils.configuration.WorkerCapabilitiesBuilder;
import org.junit.jupiter.api.Test;

import java.util.List;

import static com.czertainly.csc.utils.assertions.ResultAssertions.assertErrorContains;
import static com.czertainly.csc.utils.assertions.ResultAssertions.assertSuccessAndGet;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class WorkerRepositoryTest {


    KeyPoolProfile sessionRsa = KeyPoolProfileBuilder.create()
                                                     .withName("session_rsa")
                                                     .withKeyAlgorithm("RSA")
                                                     .withDesignatedUsage(KeyUsageDesignation.SESSION_SIGNATURE)
                                                     .build();

    KeyPoolProfile sessionEcdsa = KeyPoolProfileBuilder.create()
                                                       .withName("session_ecdsa")
                                                       .withKeyAlgorithm("ECDSA")
                                                       .withDesignatedUsage(KeyUsageDesignation.SESSION_SIGNATURE)
                                                       .build();

    KeyPoolProfile onetimeRsa = KeyPoolProfileBuilder.create()
                                                     .withName("onetime_rsa")
                                                     .withKeyAlgorithm("RSA")
                                                     .withDesignatedUsage(KeyUsageDesignation.ONE_TIME_SIGNATURE)
                                                     .build();

    KeyPoolProfile onetimeEcdsa = KeyPoolProfileBuilder.create()
                                                       .withName("onetime_ecdsa")
                                                       .withKeyAlgorithm("ECDSA")
                                                       .withDesignatedUsage(KeyUsageDesignation.ONE_TIME_SIGNATURE)
                                                       .build();

    CryptoToken ct1 = new CryptoToken("cryptoToken1", 1, List.of(sessionRsa));
    CryptoToken ct2 = new CryptoToken("cryptoToken2", 2, List.of(sessionEcdsa));
    CryptoToken ct3 = new CryptoToken("cryptoToken3", 3, List.of(onetimeRsa, onetimeEcdsa));

    Worker w1 = new Worker("worker1", 1, ct1);
    Worker w2 = new Worker("worker2", 2, ct2);
    Worker w3 = new Worker("worker3", 3, ct3);

    WorkerWithCapabilities wcap1 = new WorkerWithCapabilities(
            w1,
            WorkerCapabilitiesBuilder.create()
                                     .withConformanceLevel(ConformanceLevel.AdES_B_B)
                                     .withSignaturePackaging(SignaturePackaging.DETACHED)
                                     .build()
    );

    WorkerWithCapabilities wcap2 = new WorkerWithCapabilities(
            w2,
            WorkerCapabilitiesBuilder.create()
                                     .withConformanceLevel(ConformanceLevel.AdES_B_B)
                                     .withSignaturePackaging(SignaturePackaging.ENVELOPED)
                                     .build()
    );

    WorkerWithCapabilities wcap3 = new WorkerWithCapabilities(
            w3,
            WorkerCapabilitiesBuilder.create()
                                     .withConformanceLevel(ConformanceLevel.AdES_B_LT)
                                     .withSignaturePackaging(SignaturePackaging.ENVELOPED)
                                     .build()
    );

    List<WorkerWithCapabilities> workersWithCapabilities = List.of(wcap1, wcap2, wcap3);
    WorkerRepository workerRepository = new WorkerRepository(workersWithCapabilities);

    @Test
    void selectWorkerReturnsFirstMatchingWorker() {
        // given
        ConformanceLevelCriterion criterion = new ConformanceLevelCriterion(ConformanceLevel.AdES_B_B);

        // when
        var w = workerRepository.selectWorker(criterion);

        // then
        assertEquals("worker1", w.worker().workerName());

    }

    @Test
    void selectWorkerReturnsNullOnNoMatchingWorker() {
        // given
        // Worker repository is set up that no worker with conformance level AdES_B_LTA exists (see initialization at the top)
        ConformanceLevelCriterion criterion = new ConformanceLevelCriterion(ConformanceLevel.AdES_B_LTA);

        // when
        var w = workerRepository.selectWorker(criterion);

        // then
        assertNull(w);
    }

    @Test
    void getWorkerReturnsWorkerWithGivenId() {
        // given
        // Worker repository is set up that worker with id 2 exists (see initialization at the top)

        // when
        var w = workerRepository.getWorker(2);

        // then
        assertEquals("worker2", w.worker().workerName());
    }

    @Test
    void getWorkerReturnsNullOnNonExistingWorker() {
        // given
        // Worker repository is set up that no worker with id 4 exists (see initialization at the top)

        // when
        var w = workerRepository.getWorker(4);

        // then
        assertNull(w);
    }

    @Test
    void getCryptoTokenReturnsTokenWithGivenName() {
        // given
        // Worker repository is set up that token with name "cryptoToken2" exists (see initialization at the top)

        // when
        var result = workerRepository.getCryptoToken("cryptoToken2");

        // then
        CryptoToken token = assertSuccessAndGet(result);
        assertEquals("cryptoToken2", token.name());
    }

    @Test
    void getCryptoTokenReturnsErrorOnNonExistingToken() {
        // given
        // Worker repository is set up that no token with name "cryptoToken4" exists (see initialization at the top)

        // when
        var result = workerRepository.getCryptoToken("cryptoToken4");

        // then
        assertErrorContains(result, "Crypto token 'cryptoToken4' not found.");
    }

    @Test
    void getCryptoTokenReturnsTokenWithGivenId() {
        // given
        // Worker repository is set up that token with id 3 exists (see initialization at the top)

        // when
        var result = workerRepository.getCryptoToken(3);

        // then
        CryptoToken token = assertSuccessAndGet(result);
        assertEquals(3, token.id());
    }

    @Test
    void getCryptoTokenReturnsErrorOnNonExistingTokenId() {
        // given
        // Worker repository is set up that no token with id 4 exists (see initialization at the top)

        // when
        var result = workerRepository.getCryptoToken(4);

        // then
        assertErrorContains(result, "Crypto token with id '4' not found.");
    }


    @Test
    void getCryptoTokensWithPoolsReturnsTokensWithGivenDesignatedUsage() {
        // given
        // Worker repository is set up that tokens 1 and 2 has pools with session signature usage (see initialization at the top)

        // when
        var result = workerRepository.getCryptoTokensWithPools(KeyUsageDesignation.SESSION_SIGNATURE);

        // then
        List<CryptoToken> tokens = assertSuccessAndGet(result);
        assertEquals(2, tokens.size());
        assertEquals("cryptoToken1", tokens.get(0).name());
        assertEquals("cryptoToken2", tokens.get(1).name());
    }

    @Test
    void getCryptoTokensWithPoolsReturnAllPoolsWithGivenDesignatedUsageBelongingToTheToken() {
        // given
        // Worker repository is set up that token 3 has 2 pools with one time signature usage (see initialization at the top)

        // when
        var result = workerRepository.getCryptoTokensWithPools(KeyUsageDesignation.ONE_TIME_SIGNATURE);

        // then
        List<CryptoToken> tokens = assertSuccessAndGet(result);
        assertEquals(1, tokens.size());
        assertEquals("cryptoToken3", tokens.getFirst().name());
        assertEquals(2, tokens.getFirst().keyPoolProfiles().size());
    }
}