package com.czertainly.csc.signing.configuration.process.token;

import com.czertainly.csc.model.csc.CredentialMetadata;
import com.czertainly.csc.utils.signing.CredentialMetadataBuilder;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LongTermTokenTest {

    @Test
    void canSignDataReturnsTrueIfKeyIsConfiguredToSignAtLeastTheAmountOfDocumentsProvidedToMethod() {
        // given
        int maxDocumentsAllowedByCredential = 10;
        int maxDocumentsAllowedBySad = 10;

        // setup
        CredentialMetadata credentialMetadata = CredentialMetadataBuilder
                .create()
                .withMultisign(maxDocumentsAllowedByCredential)
                .build();
        LongTermToken longTermToken = new LongTermToken(credentialMetadata);

        // when
        boolean canSignData = longTermToken.canSignData(List.of("document1", "document2", "document3"),
                                                        maxDocumentsAllowedBySad
        );

        // then
        assertTrue(canSignData);
    }

    @Test
    void canSignDataReturnsFalseIfKeyIsConfiguredToSignLessDocumentsThanTheAmountOfDocumentsProvidedToMethod() {
        // given
        int maxDocumentsAllowedByCredential = 2;
        int maxDocumentsAllowedBySad = 2;

        // setup
        CredentialMetadata credentialMetadata = CredentialMetadataBuilder
                .create()
                .withMultisign(maxDocumentsAllowedByCredential)
                .build();
        LongTermToken longTermToken = new LongTermToken(credentialMetadata);

        // when
        boolean canSignData = longTermToken.canSignData(List.of("document1", "document2", "document3"),
                                                        maxDocumentsAllowedBySad
        );

        // then
        assertFalse(canSignData);
    }

    @Test
    void canSignDataReturnsFalseIfSadAllowsSignatureOfMoreDocumentsThanTheKey() {
        // given
        int maxDocumentsAllowedByCredential = 5;
        int maxDocumentsAllowedBySad = 10;

        // setup
        CredentialMetadata credentialMetadata = CredentialMetadataBuilder
                .create()
                .withMultisign(maxDocumentsAllowedByCredential)
                .build();
        LongTermToken longTermToken = new LongTermToken(credentialMetadata);

        // when
        boolean canSignData = longTermToken.canSignData(List.of("document1", "document2", "document3"),
                                                        maxDocumentsAllowedBySad
        );

        // then
        assertFalse(canSignData);
    }
}