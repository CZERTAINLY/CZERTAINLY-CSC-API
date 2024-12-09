package com.czertainly.csc.signing.filter;

import com.czertainly.csc.signing.configuration.WorkerCapabilities;
import com.czertainly.csc.utils.configuration.WorkerCapabilitiesBuilder;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ValidationInfoCriterionTest {

    @Test
    void matchesReturnsTrueOnMatchingValidationInfo() {
        // given
        WorkerCapabilities workerCapabilities = WorkerCapabilitiesBuilder.create()
                                                                         .withReturnsValidationInfo(true)
                                                                         .build();
        ValidationInfoCriterion validationInfoCriterion = new ValidationInfoCriterion(true);

        // when
        boolean isMatch = validationInfoCriterion.matches(workerCapabilities);

        // then
        assertTrue(isMatch);
    }

    @Test
    void matchesReturnsFalseOnNonMatchingValidationInfo() {
        // given
        WorkerCapabilities workerCapabilities = WorkerCapabilitiesBuilder.create()
                                                                         .withReturnsValidationInfo(true)
                                                                         .build();
        ValidationInfoCriterion validationInfoCriterion = new ValidationInfoCriterion(false);

        // when
        boolean isMatch = validationInfoCriterion.matches(workerCapabilities);

        // then
        assertFalse(isMatch);
    }

}