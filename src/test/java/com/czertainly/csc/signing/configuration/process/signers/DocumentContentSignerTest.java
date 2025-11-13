package com.czertainly.csc.signing.configuration.process.signers;

import com.czertainly.csc.clients.signserver.SignserverClient;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.model.Signatures;
import com.czertainly.csc.model.SignaturesWithValidationInfo;
import com.czertainly.csc.model.DocumentSignature;
import com.czertainly.csc.signing.configuration.SignaturePackaging;
import com.czertainly.csc.signing.configuration.WorkerWithCapabilities;
import com.czertainly.csc.signing.configuration.process.configuration.DocumentContentSignatureProcessConfiguration;
import com.czertainly.csc.signing.configuration.process.token.SigningToken;
import com.czertainly.csc.utils.configuration.WorkerCapabilitiesBuilder;
import com.czertainly.csc.utils.signing.DocumentContentSignatureProcessConfigurationBuilder;
import com.czertainly.csc.utils.signing.process.TestSigningToken;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Base64;
import java.util.List;

import static com.czertainly.csc.utils.assertions.ResultAssertions.assertErrorContains;
import static com.czertainly.csc.utils.assertions.ResultAssertions.assertSuccess;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DocumentContentSignerTest {

    @Mock
    SignserverClient signserverClient;

    @InjectMocks
    DocumentContentSigner<DocumentContentSignatureProcessConfiguration> documentContentSigner;

    private static final Base64.Decoder BASE64_DECODER = Base64.getDecoder();
    private static final Base64.Encoder BASE64_ENCODER = Base64.getEncoder();

    @Test
    void signCanSignSingleContent() {
        when(signserverClient.signSingleDocument(any(), any(), any(), any()))
                .thenReturn(
                        Result.success(
                                Signatures.of(
                                    DocumentSignature.of("signature".getBytes(), SignaturePackaging.CERTIFICATION)
                                )
                        )
                );

        // given
        String dataB64 = BASE64_ENCODER.encodeToString("data".getBytes());
        List<String> data = List.of(dataB64);
        DocumentContentSignatureProcessConfiguration configuration = DocumentContentSignatureProcessConfigurationBuilder
                .instance()
                .withReturnValidationInfo(false)
                .build();
        WorkerWithCapabilities worker = WorkerCapabilitiesBuilder.any();
        SigningToken signingToken = TestSigningToken.of("a-key-alias", true);

        // when
        var result = documentContentSigner.sign(data, configuration, signingToken, worker);

        // then
        assertSuccess(result);
        verify(signserverClient).signSingleDocument(
                eq(worker.worker().workerName()),
                eq(BASE64_DECODER.decode(dataB64)),
                eq(signingToken.getKeyAlias()),
                eq(configuration.signaturePackaging())
        );
    }

    @Test
    void signCanSignSingleContentWithValidationInfo() {
        when(signserverClient.signSingleDocumentWithValidationData(any(), any(), any(), any()))
                .thenReturn(Result.success(
                        SignaturesWithValidationInfo.of(DocumentSignature.of("signature".getBytes(), SignaturePackaging.CERTIFICATION))));

        // given
        String dataB64 = BASE64_ENCODER.encodeToString("data".getBytes());
        List<String> data = List.of(dataB64);
        DocumentContentSignatureProcessConfiguration configuration = DocumentContentSignatureProcessConfigurationBuilder
                .instance()
                .withReturnValidationInfo(true)
                .build();
        WorkerWithCapabilities worker = WorkerCapabilitiesBuilder.any();
        SigningToken signingToken = TestSigningToken.of("a-key-alias", true);

        // when
        var result = documentContentSigner.sign(data, configuration, signingToken, worker);

        // then
        assertSuccess(result);
        verify(signserverClient).signSingleDocumentWithValidationData(
                eq(worker.worker().workerName()),
                eq(BASE64_DECODER.decode(dataB64)),
                eq(signingToken.getKeyAlias()),
                eq(configuration.signaturePackaging())
        );
    }

    @Test
    void returnsErrorWhenMultipleContentsToSign() {
        // given
        List<String> data = List.of("data1", "data2");
        DocumentContentSignatureProcessConfiguration configuration = DocumentContentSignatureProcessConfigurationBuilder
                .instance()
                .withReturnValidationInfo(true)
                .build();
        WorkerWithCapabilities worker = WorkerCapabilitiesBuilder.any();
        SigningToken signingToken = TestSigningToken.of("a-key-alias", true);

        // when
        var result = documentContentSigner.sign(data, configuration, signingToken, worker);

        // then
        assertErrorContains(result, "Document content signing does not support multiple documents.");
    }
}