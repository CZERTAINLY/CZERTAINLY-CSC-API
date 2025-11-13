package com.czertainly.csc.signing.configuration.process.signers;

import com.czertainly.csc.clients.signserver.SignserverClient;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.model.Signatures;
import com.czertainly.csc.model.SignaturesContainer;
import com.czertainly.csc.model.SignaturesWithValidationInfo;
import com.czertainly.csc.model.DocumentSignature;
import com.czertainly.csc.signing.configuration.SignaturePackaging;
import com.czertainly.csc.signing.configuration.WorkerWithCapabilities;
import com.czertainly.csc.signing.configuration.process.configuration.DocumentHashSignatureProcessConfiguration;
import com.czertainly.csc.signing.configuration.process.token.SigningToken;
import com.czertainly.csc.utils.configuration.WorkerCapabilitiesBuilder;
import com.czertainly.csc.utils.signing.DocumentHashSignatureProcessConfigurationBuilder;
import com.czertainly.csc.utils.signing.process.TestSigningToken;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static com.czertainly.csc.utils.assertions.ResultAssertions.assertErrorContains;
import static com.czertainly.csc.utils.assertions.ResultAssertions.assertSuccess;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DocumentHashSignerTest {

    @Mock
    SignserverClient signserverClient;

    @InjectMocks
    DocumentHashSigner<DocumentHashSignatureProcessConfiguration> documentHashSigner;

    @Test
    void signCanSignSingleHash() {
        when(signserverClient.signSingleDocumentHash(any(), any(), any(), any()))
                .thenReturn(
                        Result.success(
                                Signatures.of(
                                    DocumentSignature.of("signature".getBytes(), SignaturePackaging.DETACHED)
                                )
                        )
                );

        // given
        List<String> data = List.of("data");
        DocumentHashSignatureProcessConfiguration configuration = DocumentHashSignatureProcessConfigurationBuilder
                .instance()
                .withReturnValidationInfo(false)
                .build();
        WorkerWithCapabilities worker = WorkerCapabilitiesBuilder.any();
        SigningToken signingToken = TestSigningToken.of("a-key-alias", true);

        // when
        var result = documentHashSigner.sign(data, configuration, signingToken, worker);

        // then
        assertSuccess(result);
        verify(signserverClient).signSingleDocumentHash(
                eq(worker.worker().workerName()),
                eq("data".getBytes()),
                eq(signingToken.getKeyAlias()),
                eq(configuration.digestAlgorithm())
        );
    }

    @Test
    void signCanSignSingleHashWithValidationInfo() {
        when(signserverClient.signSingleDocumentHashWithValidationData(any(), any(), any(), any()))
                .thenReturn(Result.success(
                        SignaturesWithValidationInfo.of(DocumentSignature.of("signature".getBytes(), SignaturePackaging.DETACHED))));

        // given
        List<String> data = List.of("data");
        DocumentHashSignatureProcessConfiguration configuration = DocumentHashSignatureProcessConfigurationBuilder
                .instance()
                .withReturnValidationInfo(true)
                .build();
        WorkerWithCapabilities worker = WorkerCapabilitiesBuilder.any();
        SigningToken signingToken = TestSigningToken.of("a-key-alias", true);

        // when
        var result = documentHashSigner.sign(data, configuration, signingToken, worker);

        // then
        assertSuccess(result);
        verify(signserverClient).signSingleDocumentHashWithValidationData(
                eq(worker.worker().workerName()),
                eq("data".getBytes()),
                eq(signingToken.getKeyAlias()),
                eq(configuration.digestAlgorithm())
        );
    }

    @Test
    void signCanSignMultipleHashes() {
        SignaturesContainer<DocumentSignature> signatures = Signatures.of(
                List.of(
                    DocumentSignature.of("signature1".getBytes(), SignaturePackaging.DETACHED),
                    DocumentSignature.of("signature2".getBytes(), SignaturePackaging.DETACHED)
                )
        );
        when(signserverClient.signMultipleDocumentHashes(any(), any(), any(), any()))
                .thenReturn(Result.success(signatures));

        // given
        List<String> data = List.of("data1", "data2");
        DocumentHashSignatureProcessConfiguration configuration = DocumentHashSignatureProcessConfigurationBuilder
                .instance()
                .withReturnValidationInfo(false)
                .build();
        WorkerWithCapabilities worker = WorkerCapabilitiesBuilder.any();
        SigningToken signingToken = TestSigningToken.of("a-key-alias", true);

        // when
        var result = documentHashSigner.sign(data, configuration, signingToken, worker);

        // then
        assertSuccess(result);
        verify(signserverClient).signMultipleDocumentHashes(
                eq(worker.worker().workerName()),
                eq(data),
                eq(signingToken.getKeyAlias()),
                eq(configuration.digestAlgorithm())
        );
    }

    @Test
    void signCanSignMultipleHashesWithValidationInfo() {
        SignaturesContainer<DocumentSignature> signatures = SignaturesWithValidationInfo.of(
                List.of(
                        DocumentSignature.of("signature1".getBytes(), SignaturePackaging.DETACHED),
                        DocumentSignature.of("signature2".getBytes(), SignaturePackaging.DETACHED)
                )
        );
        when(signserverClient.signMultipleDocumentHashesWithValidationData(any(), any(), any(), any()))
                .thenReturn(Result.success(signatures));

        // given
        List<String> data = List.of("data1", "data2");
        DocumentHashSignatureProcessConfiguration configuration = DocumentHashSignatureProcessConfigurationBuilder
                .instance()
                .withReturnValidationInfo(true)
                .build();
        WorkerWithCapabilities worker = WorkerCapabilitiesBuilder.any();
        SigningToken signingToken = TestSigningToken.of("a-key-alias", true);

        // when
        var result = documentHashSigner.sign(data, configuration, signingToken, worker);

        // then
        assertSuccess(result);
        verify(signserverClient).signMultipleDocumentHashesWithValidationData(
                eq(worker.worker().workerName()),
                eq(data),
                eq(signingToken.getKeyAlias()),
                eq(configuration.digestAlgorithm())
        );
    }

    @Test
    void returnsErrorWhenTheNumberOfReturnedSignaturesDoesNotMatchNumberOfInputDocuments() {
        SignaturesContainer<DocumentSignature> signatures = SignaturesWithValidationInfo.of(
                List.of(
                        DocumentSignature.of("signature1".getBytes(), SignaturePackaging.DETACHED)
                )
        );
        when(signserverClient.signMultipleDocumentHashesWithValidationData(any(), any(), any(), any()))
                .thenReturn(Result.success(signatures));

        // given
        List<String> data = List.of("data1", "data2");
        DocumentHashSignatureProcessConfiguration configuration = DocumentHashSignatureProcessConfigurationBuilder
                .instance()
                .withReturnValidationInfo(true)
                .build();
        WorkerWithCapabilities worker = WorkerCapabilitiesBuilder.any();
        SigningToken signingToken = TestSigningToken.of("a-key-alias", true);

        // when
        var result = documentHashSigner.sign(data, configuration, signingToken, worker);

        // then
        assertErrorContains(result, "The number of signatures does not match the number of documents");
    }
}