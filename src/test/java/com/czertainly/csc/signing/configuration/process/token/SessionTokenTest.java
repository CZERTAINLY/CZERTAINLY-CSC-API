package com.czertainly.csc.signing.configuration.process.token;

import com.czertainly.csc.model.csc.SessionCredentialMetadata;
import com.czertainly.csc.service.credentials.CredentialSessionStatus;
import com.czertainly.csc.service.credentials.SigningSession;
import com.czertainly.csc.utils.signing.SessionCredentialMetadataBuilder;
import com.czertainly.csc.utils.signing.aSigningSession;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SessionTokenTest {

    @Test
    void canSignDataReturnsTrueIfKeyIsConfiguredToSignAtLeastTheAmountOfDocumentsProvidedToMethod() {
        // given
        int maxDocumentsAllowedByCredential = 10;
        int maxDocumentsAllowedBySad = 10;

        // setup
        SigningSession session = aSigningSession.instance()
                                                .withStatus(CredentialSessionStatus.ACTIVE)
                                                .build();
        SessionCredentialMetadata credentialMetadata = SessionCredentialMetadataBuilder
                .create()
                .withMultisign(maxDocumentsAllowedByCredential)
                .build();
        SessionToken sessionToken = new SessionToken(credentialMetadata, session);

        // when
        boolean canSignData = sessionToken.canSignData(List.of("document1", "document2", "document3"),
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
        SigningSession session = aSigningSession.instance()
                                                .withStatus(CredentialSessionStatus.ACTIVE)
                                                .build();
        SessionCredentialMetadata credentialMetadata = SessionCredentialMetadataBuilder
                .create()
                .withMultisign(maxDocumentsAllowedByCredential)
                .build();
        SessionToken sessionToken = new SessionToken(credentialMetadata, session);

        // when
        boolean canSignData = sessionToken.canSignData(List.of("document1", "document2", "document3"),
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
        SigningSession session = aSigningSession.instance()
                                                .withStatus(CredentialSessionStatus.ACTIVE)
                                                .build();
        SessionCredentialMetadata credentialMetadata = SessionCredentialMetadataBuilder
                .create()
                .withMultisign(maxDocumentsAllowedByCredential)
                .build();
        SessionToken sessionToken = new SessionToken(credentialMetadata, session);

        // when
        boolean canSignData = sessionToken.canSignData(List.of("document1", "document2", "document3"),
                                                       maxDocumentsAllowedBySad
        );

        // then
        assertFalse(canSignData);
    }

    @Test
    void canSignDataReturnsFalseIfSessionIsNotActive() {
        // given
        CredentialSessionStatus sessionStatus = CredentialSessionStatus.EXPIRED;

        // setup
        int maxDocumentsAllowedByCredential = 10;
        int maxDocumentsAllowedBySad = 10;
        SigningSession session = aSigningSession.instance()
                                                .withStatus(sessionStatus)
                                                .build();
        SessionCredentialMetadata credentialMetadata = SessionCredentialMetadataBuilder
                .create()
                .withMultisign(maxDocumentsAllowedByCredential)
                .build();
        SessionToken sessionToken = new SessionToken(credentialMetadata, session);

        // when
        boolean canSignData = sessionToken.canSignData(List.of("document1", "document2", "document3"),
                                                       maxDocumentsAllowedBySad
        );

        // then
        assertFalse(canSignData);
    }
}