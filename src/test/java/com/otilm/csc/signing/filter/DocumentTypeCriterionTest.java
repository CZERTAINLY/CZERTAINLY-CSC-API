package com.otilm.csc.signing.filter;

import com.otilm.csc.signing.configuration.DocumentType;
import com.otilm.csc.signing.configuration.WorkerCapabilities;
import com.otilm.csc.utils.configuration.WorkerCapabilitiesBuilder;
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
