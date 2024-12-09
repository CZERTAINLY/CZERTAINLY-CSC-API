package com.czertainly.csc.signing.configuration.process.signers;

import com.czertainly.csc.clients.signserver.SignserverClient;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.model.SignedDocuments;
import com.czertainly.csc.signing.Signature;
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
        when(signserverClient.signSingleHash(any(), any(), any(), any()))
                .thenReturn(Result.success(Signature.of("signature".getBytes(), SignaturePackaging.DETACHED)));

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
        verify(signserverClient).signSingleHash(
                eq(worker.worker().workerName()),
                eq("data".getBytes()),
                eq(signingToken.getKeyAlias()),
                eq(configuration.digestAlgorithm())
        );
    }

    @Test
    void signCanSignSingleHashWithValidationInfo() {
        when(signserverClient.signSingleHashWithValidationData(any(), any(), any(), any()))
                .thenReturn(Result.success(
                        SignedDocuments.of(Signature.of("signature".getBytes(), SignaturePackaging.DETACHED))));

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
        verify(signserverClient).signSingleHashWithValidationData(
                eq(worker.worker().workerName()),
                eq("data".getBytes()),
                eq(signingToken.getKeyAlias()),
                eq(configuration.digestAlgorithm())
        );
    }

    @Test
    void signCanSignMultipleHashes() {
        List<Signature> signatures = List.of(
                Signature.of("signature1".getBytes(), SignaturePackaging.DETACHED),
                Signature.of("signature2".getBytes(), SignaturePackaging.DETACHED)
        );
        when(signserverClient.signMultipleHashes(any(), any(), any(), any()))
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
        verify(signserverClient).signMultipleHashes(
                eq(worker.worker().workerName()),
                eq(data),
                eq(signingToken.getKeyAlias()),
                eq(configuration.digestAlgorithm())
        );
    }

    @Test
    void signCanSignMultipleHashesWithValidationInfo() {
        SignedDocuments signatures = SignedDocuments.of(
                List.of(
                    Signature.of("signature1".getBytes(), SignaturePackaging.DETACHED),
                    Signature.of("signature2".getBytes(), SignaturePackaging.DETACHED)
                )
        );
        when(signserverClient.signMultipleHashesWithValidationData(any(), any(), any(), any()))
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
        verify(signserverClient).signMultipleHashesWithValidationData(
                eq(worker.worker().workerName()),
                eq(data),
                eq(signingToken.getKeyAlias()),
                eq(configuration.digestAlgorithm())
        );
    }

    @Test
    void returnsErrorWhenTheNumberOfReturnedSignaturesDoesNotMatchNumberOfInputDocuments() {
        SignedDocuments signatures = SignedDocuments.of(
                List.of(
                        Signature.of("signature1".getBytes(), SignaturePackaging.DETACHED)
                )
        );
        when(signserverClient.signMultipleHashesWithValidationData(any(), any(), any(), any()))
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