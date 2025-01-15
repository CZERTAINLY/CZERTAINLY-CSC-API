package com.czertainly.csc.clients.signserver;

import com.czertainly.csc.clients.signserver.rest.SignserverRestClient;
import com.czertainly.csc.clients.signserver.ws.SignserverWsClient;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.crypto.CertificateParser;
import com.czertainly.csc.model.SignedDocuments;
import com.czertainly.csc.signing.Signature;
import com.czertainly.csc.signing.configuration.SignaturePackaging;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.List;

import static com.czertainly.csc.utils.ResourceLoader.loadBytesFromResources;
import static com.czertainly.csc.utils.assertions.ResultAssertions.assertSuccessAndGet;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;


@ExtendWith(MockitoExtension.class)
class SignserverClientTest {

    @Mock
    SignserverWsClient signserverWSClient;
    @Mock
    SignserverRestClient signserverRestClient;
    @Spy
    KeySpecificationParser keySpecificationParser = new KeySpecificationParser();
    @Spy
    ObjectMapper objectMapper = JsonMapper.builder()
                                          .enable(StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION)
                                          .build();
    @Spy
    CertificateParser certificateParser = new CertificateParser();
    @InjectMocks
    SignserverClient signserverClient;


    SignserverClientTest() throws CertificateException {}

    String signerName = "TestSigner";
    byte[] singleHash = "dummyData1".getBytes();
    List<String> multipleHashes = List.of("dummyData1", "dummyData2");
    String keyAlias = "signingKey01";
    String digestAlgorithm = "SHA-256";


    @Test
    void signSingleHash() throws IOException {
        // given
        byte[] singleSignedHash = loadSignature("signatureSingleHash");
        when(signserverRestClient.process(eq(signerName), eq(singleHash), any(), any())).thenReturn(
                Result.success(singleSignedHash));

        // when
        var signingresult = signserverClient.signSingleHash(signerName, singleHash, keyAlias, digestAlgorithm);

        // then
        Signature signature = assertSuccessAndGet(signingresult);
        assertEquals(SignaturePackaging.DETACHED, signature.packaging());
    }

    @Test
    void signSingleHashWithValidationInfo() throws IOException {
        // given
        byte[] singleSignedHashWithValidationData = loadSignature("signatureSingleHashWithValidationData");
        when(signserverRestClient.process(eq(signerName), eq(singleHash), any(), any())).thenReturn(
                Result.success(singleSignedHashWithValidationData));

        // when
        var signingresult = signserverClient.signSingleHashWithValidationData(signerName, singleHash, keyAlias,
                                                                              digestAlgorithm
        );

        // then
        SignedDocuments signature = assertSuccessAndGet(signingresult);
        assertEquals(1, signature.signatures().size());
        assertEquals(SignaturePackaging.DETACHED, signature.signatures().getFirst().packaging());
    }

    @Test
    void signMultipleHashes() throws IOException {
        // given
        byte[] multipleSignedHashes = loadSignature("signatureMultipleHashes");
        when(signserverRestClient.process(eq(signerName), any(), any(), any())).thenReturn(
                Result.success(multipleSignedHashes));

        // when
        var signingresult = signserverClient.signMultipleHashes(signerName, multipleHashes, keyAlias, digestAlgorithm);

        // then
        List<Signature> signatures = assertSuccessAndGet(signingresult);
        assertEquals(2, signatures.size());
        assertEquals(SignaturePackaging.DETACHED, signatures.getFirst().packaging());
        assertEquals(SignaturePackaging.DETACHED, signatures.getLast().packaging());
    }

    @Test
    void signMultipleHashesWithValidationInfo() throws IOException {
        // given
        byte[] multipleSignedHashesWithValidationData = loadSignature("signatureMultipleHashesWithValidationData");
        when(signserverRestClient.process(eq(signerName), any(), any(), any())).thenReturn(
                Result.success(multipleSignedHashesWithValidationData));

        // when
        var signingresult = signserverClient.signMultipleHashesWithValidationData(signerName, multipleHashes, keyAlias,
                                                                                  digestAlgorithm
        );

        // then
        SignedDocuments signatures = assertSuccessAndGet(signingresult);
        assertEquals(2, signatures.signatures().size());
        assertEquals(SignaturePackaging.DETACHED, signatures.signatures().getFirst().packaging());
        assertEquals(SignaturePackaging.DETACHED, signatures.signatures().getLast().packaging());
    }

    private byte[] loadSignature(String name) throws IOException {
        return loadBytesFromResources("com/czertainly/csc/clients/signserver/" + name);
    }
}