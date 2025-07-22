package com.czertainly.csc.signing.filter;

import com.czertainly.csc.signing.configuration.DocumentType;
import com.czertainly.csc.signing.configuration.SignaturePackaging;
import com.czertainly.csc.signing.configuration.WorkerCapabilities;
import com.czertainly.csc.utils.configuration.WorkerCapabilitiesBuilder;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DocumentTypeCriterionTest {

    @Test
    void matchesReturnsTrueOnMatchingDocumentTypes() {
        // given
        WorkerCapabilities workerCapabilities = WorkerCapabilitiesBuilder.create()
                .withDocumentTypes(List.of(
                        DocumentType.HASH,
                        DocumentType.FULL
                ))
                .build();
        DocumentTypeCriterion documentTypeCriterion = new DocumentTypeCriterion(DocumentType.HASH);

        // when
        boolean isMatch = documentTypeCriterion.matches(workerCapabilities);

        // then
        assertTrue(isMatch);
    }

    @Test
    void matchesReturnsFalseOnNonMatchingDocumentTypes() {
        // given
        WorkerCapabilities workerCapabilities = WorkerCapabilitiesBuilder.create()
                .withDocumentTypes(List.of(
                        DocumentType.HASH
                ))
                .build();
        DocumentTypeCriterion documentTypeCriterion = new DocumentTypeCriterion(DocumentType.FULL);

        // when
        boolean isMatch = documentTypeCriterion.matches(workerCapabilities);

        // then
        assertFalse(isMatch);
    }

}
