package com.czertainly.csc.signing.configuration.process.token;

import com.czertainly.csc.service.keys.OneTimeKey;
import com.czertainly.csc.utils.signing.OneTimeKeyBuilder;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OneTimeTokenTest {

    @Test
    void canSignDataReturnsTrueIfKeyIsConfiguredToSignAtLeastTheAmountOfDocumentsProvidedToMethod() {
        // given
        int maxDocumentsAllowedByToken = 10;
        int maxDocumentsAllowedBySad = 10;

        // setup
        OneTimeKey oneTimeKey = OneTimeKeyBuilder.aOneTimeKey();
        OneTimeToken oneTimeToken = new OneTimeToken(oneTimeKey, maxDocumentsAllowedByToken);

        // when
        boolean canSignData = oneTimeToken.canSignData(List.of("document1", "document2", "document3"),
                                                       maxDocumentsAllowedBySad
        );

        // then
        assertTrue(canSignData);
    }

    @Test
    void canSignDataReturnsFalseIfKeyIsConfiguredToSignLessDocumentsThanTheAmountOfDocumentsProvidedToMethod() {
        // given
        int maxDocumentsAllowedByToken = 2;
        int maxDocumentsAllowedBySad = 2;

        // setup
        OneTimeKey oneTimeKey = OneTimeKeyBuilder.aOneTimeKey();
        OneTimeToken oneTimeToken = new OneTimeToken(oneTimeKey, maxDocumentsAllowedByToken);

        // when
        boolean canSignData = oneTimeToken.canSignData(List.of("document1", "document2", "document3"),
                                                       maxDocumentsAllowedBySad
        );

        // then
        assertFalse(canSignData);
    }

    @Test
    void canSignDataReturnsFalseIfSadAllowsSignatureOfMoreDocumentsThanTheKey() {
        // given
        int maxDocumentsAllowedByToken = 5;
        int maxDocumentsAllowedBySad = 10;

        // setup
        OneTimeKey oneTimeKey = OneTimeKeyBuilder.aOneTimeKey();
        OneTimeToken oneTimeToken = new OneTimeToken(oneTimeKey, maxDocumentsAllowedByToken);

        // when
        boolean canSignData = oneTimeToken.canSignData(List.of("document1", "document2", "document3"),
                                                       maxDocumentsAllowedBySad
        );

        // then
        assertFalse(canSignData);
    }
}