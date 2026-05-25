package com.otilm.csc.signing.filter;

import com.otilm.csc.signing.configuration.SignatureFormat;
import com.otilm.csc.signing.configuration.WorkerCapabilities;
import com.otilm.csc.utils.configuration.WorkerCapabilitiesBuilder;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignatureFormatCriterionTest {

    @Test
    void matchesReturnsTrueOnMatchingSignatureFormat() {
        // given
        WorkerCapabilities workerCapabilities = WorkerCapabilitiesBuilder.create()
                                                                         .withSignatureFormat(SignatureFormat.XAdES)
                                                                         .build();
        SignatureFormatCriterion signatureFormatCriterion = new SignatureFormatCriterion(SignatureFormat.XAdES);

        // when
        boolean isMatch = signatureFormatCriterion.matches(workerCapabilities);

        // then
        assertTrue(isMatch);
    }

    @Test
    void matchesReturnsFalseOnNonMatchingSignatureFormat() {
        // given
        WorkerCapabilities workerCapabilities = WorkerCapabilitiesBuilder.create()
                                                                         .withSignatureFormat(SignatureFormat.XAdES)
                                                                         .build();
        SignatureFormatCriterion signatureFormatCriterion = new SignatureFormatCriterion(SignatureFormat.CAdES);

        // when
        boolean isMatch = signatureFormatCriterion.matches(workerCapabilities);

        // then
        assertFalse(isMatch);
    }

}