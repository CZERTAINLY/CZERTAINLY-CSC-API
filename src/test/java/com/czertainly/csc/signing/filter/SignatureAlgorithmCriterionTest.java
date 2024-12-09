package com.czertainly.csc.signing.filter;

import com.czertainly.csc.signing.configuration.WorkerCapabilities;
import com.czertainly.csc.utils.configuration.WorkerCapabilitiesBuilder;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SignatureAlgorithmCriterionTest {

    @Test
    void matchesReturnsTrueOnMatchingSignatureAlgorithm() {
         //given
         WorkerCapabilities workerCapabilities = WorkerCapabilitiesBuilder.create()
                                                                          .withSupportedSignatureAlgorithms(
                                                                                  List.of("SHA256WithRSA", "SHA512WithRSA"))
                                                                          .build();
         SignatureAlgorithmCriterion signatureAlgorithmCriterion = new SignatureAlgorithmCriterion("SHA512WithRSA");

         // when
         boolean isMatch = signatureAlgorithmCriterion.matches(workerCapabilities);

         // then
         assertTrue(isMatch);
    }

    @Test
    void matchesReturnsFalseOnNonMatchingSignatureAlgorithm() {
        //given
        WorkerCapabilities workerCapabilities = WorkerCapabilitiesBuilder.create()
                                                                         .withSupportedSignatureAlgorithms(
                                                                                 List.of("SHA256WithRSA", "SHA512WithRSA"))
                                                                         .build();
        SignatureAlgorithmCriterion signatureAlgorithmCriterion = new SignatureAlgorithmCriterion("SHA384WithRSA");

        // when
        boolean isMatch = signatureAlgorithmCriterion.matches(workerCapabilities);

        // then
        assertFalse(isMatch);
    }

}