package com.czertainly.csc.signing.configuration.process;

import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.crypto.SignatureAlgorithm;
import com.czertainly.csc.model.DocumentSignature;
import com.czertainly.csc.model.SignaturesContainer;
import com.czertainly.csc.model.SignaturesWithValidationInfo;
import com.czertainly.csc.signing.configuration.*;
import com.czertainly.csc.signing.configuration.process.signers.Signer;
import com.czertainly.csc.signing.configuration.process.token.TokenProvider;
import com.czertainly.csc.signing.filter.Criterion;
import com.czertainly.csc.signing.signatureauthorizers.SignatureAuthorizer;
import com.czertainly.csc.utils.configuration.WorkerCapabilitiesBuilder;
import com.czertainly.csc.utils.signing.process.TestSignatureProcessConfiguration;
import com.czertainly.csc.utils.signing.process.TestSigningToken;
import com.czertainly.csc.utils.signing.process.TestTokenConfiguration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static com.czertainly.csc.utils.assertions.ResultAssertions.assertErrorContains;
import static com.czertainly.csc.utils.assertions.ResultAssertions.assertSuccessAndGet;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SignatureProcessTemplateTest {

    @Mock
    SignatureAuthorizer signatureAuthorizer;

    @Mock
    WorkerRepository workerRepository;

    @Mock
    TokenProvider<TestTokenConfiguration, TestSignatureProcessConfiguration, TestSigningToken> testTokenProvider;

    @Mock
    Signer<TestSignatureProcessConfiguration, DocumentSignature> signer;

    @InjectMocks
    SignatureProcessTemplate<TestTokenConfiguration, TestSignatureProcessConfiguration, TestSigningToken, DocumentSignature> testSignatureProcessTemplate;

    List<String> dataToSign = List.of("data");

    TestTokenConfiguration testTokenConfiguration = TestTokenConfiguration.any();

    TestSignatureProcessConfiguration processConfiguration = TestSignatureProcessConfiguration.any();


    @Test
    void signReturnsErrorIfSignatureNotAuthorized() {
        // given
        when(signatureAuthorizer.authorize(dataToSign, processConfiguration.sad())).thenReturn(Result.success(false));

        // when
        var result = testSignatureProcessTemplate.sign(processConfiguration, testTokenConfiguration, dataToSign);

        // then
        assertErrorContains(result, "Signature request was not authorized");
    }

    @Test
    void signReturnsErrorIfAuthorizationFails() {
        // given
        when(signatureAuthorizer.authorize(dataToSign, processConfiguration.sad())).thenReturn(
                Result.error(TextError.of("Some error")));

        // when
        var result = testSignatureProcessTemplate.sign(processConfiguration, testTokenConfiguration, dataToSign);

        // then
        assertErrorContains(result, "Failed to authorize signature request");
    }

    @Test
    void signSelectsWorkerBasedOnTheSignatureProcessConfiguration() {
        // setup
        when(signatureAuthorizer.authorize(any(), any())).thenReturn(Result.success(true));
        when(workerRepository.selectWorker(any())).thenReturn(null); // just return null to stop the process

        // given
        processConfiguration = TestSignatureProcessConfiguration.builder()
                                                                .withSignatureQualifier("qualified")
                                                                .withSignatureFormat(SignatureFormat.PAdES)
                                                                .withSignatureAlgorithm(
                                                                        SignatureAlgorithm.fromJavaName(
                                                                                "SHA256WithRSA"))
                                                                .withSignaturePackaging(SignaturePackaging.DETACHED)
                                                                .withConformanceLevel(ConformanceLevel.AdES_B_B)
                                                                .withReturnValidationInfo(true)
                                                                .build();

        // when
        testSignatureProcessTemplate.sign(processConfiguration, testTokenConfiguration, dataToSign);

        // then
        ArgumentCaptor<Criterion<WorkerCapabilities>> captor = ArgumentCaptor.forClass(Criterion.class);
        verify(workerRepository).selectWorker(captor.capture());
        Criterion<WorkerCapabilities> criterion = captor.getValue();

        // Must match WorkerCapabilities with the same values as in the processConfiguration
        var correctCapabilities = fromProcessConfiguration(processConfiguration).build();
        assertTrue(criterion.matches(correctCapabilities));

        // Must not match WorkerCapabilities that differ in any of the values
        var withNotMatchingSignatureQualifiers = fromProcessConfiguration(processConfiguration)
                .withSignatureQualifiers(List.of("not-matching"))
                .build();
        assertFalse(criterion.matches(withNotMatchingSignatureQualifiers));

        var withNotMatchingSignatureFormat = fromProcessConfiguration(processConfiguration)
                .withSignatureFormat(SignatureFormat.CAdES)
                .build();
        assertFalse(criterion.matches(withNotMatchingSignatureFormat));

        var withNotMatchingConformanceLevel = fromProcessConfiguration(processConfiguration)
                .withConformanceLevel(ConformanceLevel.AdES_B_T)
                .build();
        assertFalse(criterion.matches(withNotMatchingConformanceLevel));

        var withNotMatchingSignaturePackaging = fromProcessConfiguration(processConfiguration)
                .withSignaturePackaging(SignaturePackaging.ENVELOPING)
                .build();
        assertFalse(criterion.matches(withNotMatchingSignaturePackaging));

        var withNotMatchingSignatureAlgorithm = fromProcessConfiguration(processConfiguration)
                .withSupportedSignatureAlgorithms(List.of("SHA1WithRSA"))
                .build();
        assertFalse(criterion.matches(withNotMatchingSignatureAlgorithm));

        var withNotMatchingReturnValidationInfo = fromProcessConfiguration(processConfiguration)
                .withReturnsValidationInfo(false)
                .build();
        assertFalse(criterion.matches(withNotMatchingReturnValidationInfo));
    }

    @Test
    void signReturnsErrorIfNoWorkerFound() {
        // setup
        when(signatureAuthorizer.authorize(any(), any())).thenReturn(Result.success(true));
        when(workerRepository.selectWorker(any())).thenReturn(null);

        // given
        processConfiguration = TestSignatureProcessConfiguration.any();

        // when
        var result = testSignatureProcessTemplate.sign(processConfiguration, testTokenConfiguration, dataToSign);

        // then
        assertErrorContains(result, "Failed to obtain suitable worker for the signature request");
    }

    @Test
    void signReturnsErrorIfObtainingSigningTokenFails() {
        // setup
        when(signatureAuthorizer.authorize(any(), any())).thenReturn(Result.success(true));
        when(workerRepository.selectWorker(any())).thenReturn(WorkerCapabilitiesBuilder.any());

        // given
        when(testTokenProvider.getSigningToken(any(), any(), any())).thenReturn(
                Result.error(TextError.of("Some error")));

        // when
        var result = testSignatureProcessTemplate.sign(processConfiguration, testTokenConfiguration, dataToSign);

        // then
        assertErrorContains(result, "Failed to get signing token for the signature request");
    }

    @Test
    void signReturnsErrorIfSigningTokenCantSignData() {
        // setup
        when(signatureAuthorizer.authorize(any(), any())).thenReturn(Result.success(true));
        when(workerRepository.selectWorker(any())).thenReturn(WorkerCapabilitiesBuilder.any());

        // given
        when(testTokenProvider.getSigningToken(any(), any(), any()))
                .thenReturn(Result.success(TestSigningToken.of("an-alias", false)));

        // when
        var result = testSignatureProcessTemplate.sign(processConfiguration, testTokenConfiguration, dataToSign);

        // then
        assertErrorContains(result, "Selected signing token cannot sign the requested data");
    }

    @Test
    void signReturnsErrorIfSigningFails() {
        // setup
        when(signatureAuthorizer.authorize(any(), any())).thenReturn(Result.success(true));
        when(workerRepository.selectWorker(any())).thenReturn(WorkerCapabilitiesBuilder.any());
        when(testTokenProvider.getSigningToken(any(), any(), any())).thenReturn(Result.success(TestSigningToken.any()));

        // given
        when(signer.sign(any(), any(), any(), any())).thenReturn(Result.error(TextError.of("Some error")));

        // when
        var result = testSignatureProcessTemplate.sign(processConfiguration, testTokenConfiguration, dataToSign);

        // then
        assertErrorContains(result, "Error occurred during signing");
    }

    @Test
    void signReturnsSuccessIfSigningSucceeds() {
        // setup
        var woker = WorkerCapabilitiesBuilder.any();
        var signingToken = TestSigningToken.any();

        when(signatureAuthorizer.authorize(dataToSign, processConfiguration.sad()))
                .thenReturn(Result.success(true));
        when(workerRepository.selectWorker(any()))
                .thenReturn(woker);
        when(testTokenProvider.getSigningToken(processConfiguration, testTokenConfiguration, woker)).thenReturn(
                Result.success(signingToken));

        // given
        SignaturesContainer<DocumentSignature> docs = Mockito.mock(SignaturesWithValidationInfo.class);
        when(signer.sign(dataToSign, processConfiguration, signingToken, woker))
                .thenReturn(Result.success(docs));

        // when
        var result = testSignatureProcessTemplate.sign(processConfiguration, testTokenConfiguration, dataToSign);

        // then
        SignaturesContainer<DocumentSignature> signedDocs = assertSuccessAndGet(result);
        assertEquals(docs, signedDocs);
    }

    WorkerCapabilitiesBuilder fromProcessConfiguration(TestSignatureProcessConfiguration configuration) {
        return WorkerCapabilitiesBuilder.create()
                                        .withSignatureQualifiers(List.of(configuration.signatureQualifier()))
                                        .withSignatureFormat(configuration.signatureFormat())
                                        .withConformanceLevel(configuration.conformanceLevel())
                                        .withSupportedSignatureAlgorithms(
                                                List.of(configuration.signatureAlgorithm().toJavaName()))
                                        .withSignaturePackaging(configuration.signaturePackaging())
                                        .withReturnsValidationInfo(configuration.returnValidationInfo());
    }

}