package com.czertainly.csc.signing.filter;

import com.czertainly.csc.signing.configuration.ConformanceLevel;
import com.czertainly.csc.signing.configuration.SignatureFormat;
import com.czertainly.csc.signing.configuration.SignaturePackaging;
import com.czertainly.csc.signing.configuration.WorkerCapabilities;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CriterionTest {

    private final WorkerCapabilities validWorkerCapabilities = new WorkerCapabilities(
            List.of("eu_eidas_qes", "eu_eidas_aes"),
            SignatureFormat.XAdES,
            ConformanceLevel.AdES_B_B,
            SignaturePackaging.DETACHED,
            List.of("SHA256withRSA", "SHA384withRSA", "SHA512withRSA"),
            false
    );

    @ParameterizedTest
    @MethodSource("provideCriterionAndExpectedMatches")
    void criterionTest(Criterion<WorkerCapabilities> criterion, boolean expected) {
        // given
        // provided criterion

        // when
        boolean matches = criterion.matches(validWorkerCapabilities);

        // then
        assertEquals(expected, matches);
    }

    private static Stream<Arguments> provideCriterionAndExpectedMatches() {
        AndCriterion<WorkerCapabilities> matchingCriterion = new AndCriterion<>();
        matchingCriterion.add(new SignatureQualifierCriterion("eu_eidas_qes"));
        matchingCriterion.add(new SignatureFormatCriterion(SignatureFormat.XAdES));
        matchingCriterion.add(new ConformanceLevelCriterion(ConformanceLevel.AdES_B_B));
        matchingCriterion.add(new SignaturePackagingCriterion(SignaturePackaging.DETACHED));
        matchingCriterion.add(new SignatureAlgorithmCriterion("SHA256withRSA"));
        matchingCriterion.add(new ValidationInfoCriterion(false));

        AndCriterion<WorkerCapabilities> nonMatchingCriterion = new AndCriterion<>();
        nonMatchingCriterion.add(new SignatureQualifierCriterion("eu_eidas_qes"));
        nonMatchingCriterion.add(new SignatureFormatCriterion(SignatureFormat.PAdES)); // does not match
        nonMatchingCriterion.add(new ConformanceLevelCriterion(ConformanceLevel.AdES_B_B));
        nonMatchingCriterion.add(new SignaturePackagingCriterion(SignaturePackaging.DETACHED));
        nonMatchingCriterion.add(new SignatureAlgorithmCriterion("SHA256withRSA"));
        nonMatchingCriterion.add(new ValidationInfoCriterion(false));

        return Stream.of(
                Arguments.of(matchingCriterion, true),
                Arguments.of(nonMatchingCriterion, false)
        );
    }
}
