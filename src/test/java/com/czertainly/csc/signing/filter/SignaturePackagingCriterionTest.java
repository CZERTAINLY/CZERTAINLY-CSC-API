package com.czertainly.csc.signing.filter;

import com.czertainly.csc.signing.configuration.SignaturePackaging;
import com.czertainly.csc.signing.configuration.WorkerCapabilities;
import com.czertainly.csc.utils.configuration.WorkerCapabilitiesBuilder;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SignaturePackagingCriterionTest {

    @Test
    void matchesReturnsTrueOnMatchingSignaturePackaging() {
        // given
        WorkerCapabilities workerCapabilities = WorkerCapabilitiesBuilder.create()
                                                                         .withSignaturePackaging(SignaturePackaging.DETACHED)
                                                                         .build();
        SignaturePackagingCriterion signaturePackagingCriterion = new SignaturePackagingCriterion(SignaturePackaging.DETACHED);

        // when
        boolean isMatch = signaturePackagingCriterion.matches(workerCapabilities);

        // then
        assertTrue(isMatch);
    }

    @Test
    void matchesReturnsFalseOnNonMatchingSignaturePackaging() {
        // given
        WorkerCapabilities workerCapabilities = WorkerCapabilitiesBuilder.create()
                                                                         .withSignaturePackaging(SignaturePackaging.DETACHED)
                                                                         .build();
        SignaturePackagingCriterion signaturePackagingCriterion = new SignaturePackagingCriterion(SignaturePackaging.ENVELOPING);

        // when
        boolean isMatch = signaturePackagingCriterion.matches(workerCapabilities);

        // then
        assertFalse(isMatch);
    }

}