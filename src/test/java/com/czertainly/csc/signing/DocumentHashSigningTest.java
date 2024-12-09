//package com.czertainly.csc.signing;
//
//import com.czertainly.csc.api.auth.CscAuthenticationToken;
//import com.czertainly.csc.common.result.Result;
//import com.czertainly.csc.common.result.TextError;
//import com.czertainly.csc.model.DocumentDigestsToSign;
//import com.czertainly.csc.model.SignDocParameters;
//import com.czertainly.csc.model.SignedDocuments;
//import com.czertainly.csc.signing.configuration.process.DocumentHashSignatureProcessTemplate;
//import com.czertainly.csc.signing.configuration.process.configuration.DocumentHashSignatureProcessConfiguration;
//import com.czertainly.csc.signing.configuration.process.configuration.LongTermTokenConfiguration;
//import com.czertainly.csc.signing.configuration.process.configuration.OneTimeTokenConfiguration;
//import com.czertainly.csc.signing.configuration.process.configuration.SessionTokenConfiguration;
//import com.czertainly.csc.signing.configuration.process.token.LongTermToken;
//import com.czertainly.csc.signing.configuration.process.token.OneTimeToken;
//import com.czertainly.csc.signing.configuration.process.token.SessionToken;
//import org.junit.jupiter.api.BeforeEach;
//import org.junit.jupiter.api.Test;
//import org.junit.jupiter.api.extension.ExtendWith;
//import org.mockito.Mock;
//import org.mockito.junit.jupiter.MockitoExtension;
//
//import java.util.Collections;
//import java.util.List;
//import java.util.Optional;
//import java.util.UUID;
//
//import static org.junit.jupiter.api.Assertions.assertEquals;
//import static org.mockito.ArgumentMatchers.any;
//import static org.mockito.Mockito.lenient;
//import static org.mockito.Mockito.mock;
//import static org.mockito.Mockito.verify;
//import static org.mockito.Mockito.verifyNoInteractions;
//import static org.mockito.Mockito.when;
//
//@ExtendWith(MockitoExtension.class)
//class DocumentHashSigningTest {
//
//    @Mock
//    private DocumentHashSignatureProcessTemplate<OneTimeTokenConfiguration, DocumentHashSignatureProcessConfiguration, OneTimeToken> oneTimeHashSignature;
//
//    @Mock
//    private DocumentHashSignatureProcessTemplate<LongTermTokenConfiguration, DocumentHashSignatureProcessConfiguration, LongTermToken> longTermHashSignature;
//
//    @Mock
//    private DocumentHashSignatureProcessTemplate<SessionTokenConfiguration, DocumentHashSignatureProcessConfiguration, SessionToken> sessionSignature;
//
//    @Mock
//    private DocumentHashSignatureProcessTemplateFactory documentHashSignatureProcessTemplateFactory;
//
//    // Object under test
//    private DocumentHashSigning documentHashSigning;
//
//    @Mock
//    private SignDocParameters parameters;
//
//    @Mock
//    private CscAuthenticationToken authToken;
//
//    @BeforeEach
//    void setup() {
//        lenient()
//                .when(documentHashSignatureProcessTemplateFactory.createOneTimeDocumentHashSignatureProcessTemplate())
//                .thenReturn(oneTimeHashSignature);
//        lenient()
//                .when(documentHashSignatureProcessTemplateFactory.createLongTermDocumentHashSignatureProcessTemplate())
//                .thenReturn(longTermHashSignature);
//        lenient()
//                .when(documentHashSignatureProcessTemplateFactory.createSessionDocumentHashSignatureProcessTemplate())
//                .thenReturn(sessionSignature);
//        documentHashSigning = new DocumentHashSigning(documentHashSignatureProcessTemplateFactory);
//    }
//
//    @Test
//    void signReturnsErrorWhenNoDocumentsToSign() {
//        // given
//        when(parameters.documentDigestsToSign()).thenReturn(Collections.emptyList());
//
//        // when
//        Result<SignedDocuments, TextError> result = documentHashSigning.sign(parameters, authToken);
//
//        // then
//        assertEquals("No document digests to sign.", result.unwrapError().getErrorText());
//        verifyNoInteractions(oneTimeHashSignature, longTermHashSignature, sessionSignature);
//    }
//
//    @Test
//    void signUsesOneTimeSignatureWhenNoSessionIdAndNoCredentialIdIsSupplied() {
//        // given
//        when(parameters.documentDigestsToSign()).thenReturn(List.of(mock(DocumentDigestsToSign.class)));
//        when(parameters.sessionId()).thenReturn(Optional.empty());
//        when(parameters.credentialID()).thenReturn(null);
//        when(oneTimeHashSignature.sign(any(), any(), any())).thenReturn(Result.success(mock()));
//
//        // then
//        documentHashSigning.sign(parameters, authToken);
//
//        // then
//        verify(oneTimeHashSignature).sign(any(), any(), any());
//        verifyNoInteractions(longTermHashSignature, sessionSignature);
//    }
//
//    @Test
//    void signUsesLongTermSignatureWhenNoSessionIdAndCredentialIdIsSupplied() {
//        // given
//        when(parameters.documentDigestsToSign()).thenReturn(List.of(mock(DocumentDigestsToSign.class)));
//        when(parameters.sessionId()).thenReturn(Optional.empty());
//        when(parameters.credentialID()).thenReturn(UUID.randomUUID());
//        when(longTermHashSignature.sign(any(), any(), any())).thenReturn(Result.success(mock()));
//
//        // when
//        documentHashSigning.sign(parameters, authToken);
//
//        // then
//        verify(longTermHashSignature).sign(any(), any(), any());
//        verifyNoInteractions(oneTimeHashSignature, sessionSignature);
//    }
//
//    @Test
//    void signUsesSessionSignatureWhenSessionIdIsSupplied() {
//        // given
//        when(parameters.documentDigestsToSign()).thenReturn(List.of(mock(DocumentDigestsToSign.class)));
//        when(parameters.sessionId()).thenReturn(Optional.of(UUID.randomUUID()));
//        when(sessionSignature.sign(any(), any(), any())).thenReturn(Result.success(mock()));
//
//        // when
//        documentHashSigning.sign(parameters, authToken);
//
//        // then
//        verify(sessionSignature).sign(any(), any(), any());
//        verifyNoInteractions(oneTimeHashSignature, longTermHashSignature);
//    }
//}
