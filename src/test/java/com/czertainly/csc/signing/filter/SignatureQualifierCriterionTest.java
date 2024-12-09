package com.czertainly.csc.signing.filter;

import com.czertainly.csc.signing.configuration.WorkerCapabilities;
import com.czertainly.csc.utils.configuration.WorkerCapabilitiesBuilder;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SignatureQualifierCriterionTest {

    @Test
    void matchesReturnsTrueOnMatchingSignatureQualifier() {
        // given
        WorkerCapabilities workerCapabilities = WorkerCapabilitiesBuilder.create()
                                                                         .withSignatureQualifiers(
                                                                                 List.of("eu_eidas_qes", "eu_eidas_aes")
                                                                         )
                                                                         .build();
        SignatureQualifierCriterion signatureQualifierCriterion = new SignatureQualifierCriterion("eu_eidas_aes");

        // when
        boolean isMatch = signatureQualifierCriterion.matches(workerCapabilities);

        // then
        assertTrue(isMatch);
    }

    @Test
    void matchesReturnsFalseOnNonMatchingSignatureQualifier() {
        // given
        WorkerCapabilities workerCapabilities = WorkerCapabilitiesBuilder.create()
                                                                         .withSignatureQualifiers(
                                                                                 List.of("eu_eidas_qes", "eu_eidas_aes")
                                                                         )
                                                                         .build();
        SignatureQualifierCriterion signatureQualifierCriterion = new SignatureQualifierCriterion("custom_qualifier");

        // when
        boolean isMatch = signatureQualifierCriterion.matches(workerCapabilities);

        // then
        assertFalse(isMatch);
    }

}