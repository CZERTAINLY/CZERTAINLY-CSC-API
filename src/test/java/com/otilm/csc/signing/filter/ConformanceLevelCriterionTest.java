package com.otilm.csc.signing.filter;

import com.otilm.csc.signing.configuration.ConformanceLevel;
import com.otilm.csc.signing.configuration.WorkerCapabilities;
import com.otilm.csc.utils.configuration.WorkerCapabilitiesBuilder;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConformanceLevelCriterionTest {

    @Test
    void matchesReturnsTrueOnMatchingConformanceLevel() {
        // given
        WorkerCapabilities workerCapabilities = WorkerCapabilitiesBuilder.create()
                                                                         .withConformanceLevel(
                                                                                 ConformanceLevel.AdES_B_B)
                                                                         .build();
        ConformanceLevelCriterion conformanceLevelCriterion = new ConformanceLevelCriterion(ConformanceLevel.AdES_B_B);

        // when
        boolean isMatch = conformanceLevelCriterion.matches(workerCapabilities);

        // then
        assertTrue(isMatch);
    }

    @Test
    void matchesReturnsFalseOnNonMatchingConformanceLevel() {
        // given
        WorkerCapabilities workerCapabilities = WorkerCapabilitiesBuilder.create()
                                                                         .withConformanceLevel(
                                                                                 ConformanceLevel.AdES_B_B)
                                                                         .build();
        ConformanceLevelCriterion conformanceLevelCriterion = new ConformanceLevelCriterion(ConformanceLevel.AdES_B_LT);

        // when
        boolean isMatch = conformanceLevelCriterion.matches(workerCapabilities);

        // then
        assertFalse(isMatch);
    }

}