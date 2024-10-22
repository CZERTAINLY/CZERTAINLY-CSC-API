package com.czertainly.csc.api.mappers.signatures;

import com.czertainly.csc.api.signdoc.SignDocResponseDto;
import com.czertainly.csc.api.signdoc.ValidationInfo;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.model.SignedDocuments;
import com.czertainly.csc.signing.Signature;
import com.czertainly.csc.signing.configuration.SignaturePackaging;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class SignDocResponseMapperTest {

    SignDocResponseMapper mapper = new SignDocResponseMapper();
    Base64.Encoder encoder = Base64.getEncoder();

    @Test
    void canMapRequest() {
        // given
        SignedDocuments model = aSignedDocuments();

        // when
        Result<SignDocResponseDto, TextError> result = mapper.map(model);

        // then
        assertNotNull(result);
    }

    @Test
    void canMapValidationInfo() {
        // given
        List<String> crls = List.of("crl1", "crl2");
        List<String> ocsps = List.of("ocsp1", "ocsp2");
        List<String> certs = List.of("cert1", "cert2");
        SignedDocuments model = aSignedDocuments(crls, ocsps, certs);

        // when
        Result<SignDocResponseDto, TextError> result = mapper.map(model);

        // then
        ValidationInfo validationInfo = result.unwrap().getValidationInfo();
        assertNotNull(validationInfo);
        assertContainsExactlyInAnyOrder(crls, validationInfo.crl());
        assertContainsExactlyInAnyOrder(ocsps, validationInfo.ocsp());
        assertContainsExactlyInAnyOrder(certs, validationInfo.certificates());
    }

    @Test
    void splitsSignaturesToDocumentWithSignaturesAndStandaloneSignatures() {
        // given
        List<Signature> signatures = List.of(
                new Signature("enveloped".getBytes(), SignaturePackaging.ENVELOPED),
                new Signature("detached".getBytes(), SignaturePackaging.DETACHED)
        );
        String encodedEnveloped = encoder.encodeToString("enveloped".getBytes());
        String encodedDetached = encoder.encodeToString("detached".getBytes());
        SignedDocuments model = aSignedDocuments(signatures);

        // when
        Result<SignDocResponseDto, TextError> result = mapper.map(model);

        // then
        SignDocResponseDto response = result.unwrap();
        assertEquals(1, response.getDocumentWithSignature().size());
        assertEquals(encodedEnveloped, response.getDocumentWithSignature().getFirst());
        assertEquals(1, response.getSignatureObject().size());
        assertEquals(encodedDetached, response.getSignatureObject().getFirst());
    }

    void signaturesAreBase64Encoded() {
        // given
        List<Signature> signatures = List.of(
                new Signature("enveloped".getBytes(), SignaturePackaging.ENVELOPED),
                new Signature("detached".getBytes(), SignaturePackaging.DETACHED)
        );
        String encodedEnveloped = encoder.encodeToString("enveloped".getBytes());
        String encodedDetached = encoder.encodeToString("detached".getBytes());
        SignedDocuments model = aSignedDocuments(signatures);

        // when
        Result<SignDocResponseDto, TextError> result = mapper.map(model);

        // then
        SignDocResponseDto response = result.unwrap();
        assertEquals(encodedEnveloped, response.getDocumentWithSignature().getFirst());
        assertEquals(encodedDetached, response.getSignatureObject().getFirst());
    }

    @Test
    void canMapValidationInfoWithEmptyCerts() {
        // given
        List<String> crls = List.of("crl1", "crl2");
        List<String> ocsps = List.of("ocsp1", "ocsp2");
        List<String> certs = List.of();
        SignedDocuments model = aSignedDocuments(crls, ocsps, certs);

        // when
        Result<SignDocResponseDto, TextError> result = mapper.map(model);

        // then
        ValidationInfo validationInfo = result.unwrap().getValidationInfo();
        assertNotNull(validationInfo);
        assertContainsExactlyInAnyOrder(crls, validationInfo.crl());
        assertContainsExactlyInAnyOrder(ocsps, validationInfo.ocsp());
        assertContainsExactlyInAnyOrder(certs, validationInfo.certificates());
    }

    @Test
    void canMapValidationInfoWithEmptyOcsps() {
        // given
        List<String> crls = List.of("crl1", "crl2");
        List<String> ocsps = List.of();
        List<String> certs = List.of("cert1", "cert2");
        SignedDocuments model = aSignedDocuments(crls, ocsps, certs);

        // when
        Result<SignDocResponseDto, TextError> result = mapper.map(model);

        // then
        ValidationInfo validationInfo = result.unwrap().getValidationInfo();
        assertNotNull(validationInfo);
        assertContainsExactlyInAnyOrder(crls, validationInfo.crl());
        assertContainsExactlyInAnyOrder(ocsps, validationInfo.ocsp());
        assertContainsExactlyInAnyOrder(certs, validationInfo.certificates());
    }

    @Test
    void canMapValidationInfoWithEmptyCrls() {
        // given
        List<String> crls = List.of();
        List<String> ocsps = List.of("ocsp1", "ocsp2");
        List<String> certs = List.of("cert1", "cert2");
        SignedDocuments model = aSignedDocuments(crls, ocsps, certs);

        // when
        Result<SignDocResponseDto, TextError> result = mapper.map(model);

        // then
        ValidationInfo validationInfo = result.unwrap().getValidationInfo();
        assertNotNull(validationInfo);
        assertContainsExactlyInAnyOrder(crls, validationInfo.crl());
        assertContainsExactlyInAnyOrder(ocsps, validationInfo.ocsp());
        assertContainsExactlyInAnyOrder(certs, validationInfo.certificates());
    }


    @Test
    void canMapRequestWithEmptyCertsCrlsOcsps() {
        // given
        SignedDocuments model = new SignedDocuments(
                List.of(
                        new Signature(
                                new byte[]{1, 2, 3},
                                SignaturePackaging.ENVELOPED
                        )
                ),
                Set.of(),
                Set.of(),
                Set.of()
        );

        // when
        Result<SignDocResponseDto, TextError> result = mapper.map(model);

        // then
        assertNull(result.unwrap().getValidationInfo());
    }

    SignedDocuments aSignedDocuments() {
        return new SignedDocuments(
                List.of(
                        new Signature(
                                new byte[]{1, 2, 3},
                                SignaturePackaging.ENVELOPED
                        ),
                        new Signature(
                                new byte[]{4, 5, 6},
                                SignaturePackaging.DETACHED
                        )
                ),
                Set.of("crl1", "crl2"),
                Set.of("ocsp1", "ocsp2"),
                Set.of("cert1", "cert2")
            );
    }

    SignedDocuments aSignedDocuments(List<String> crls, List<String> ocsps, List<String> certs) {
        return new SignedDocuments(
                List.of(
                        new Signature(
                                new byte[]{1, 2, 3},
                                SignaturePackaging.ENVELOPED
                        ),
                        new Signature(
                                new byte[]{4, 5, 6},
                                SignaturePackaging.DETACHED
                        )
                ),
                new HashSet<>(crls),
                new HashSet<>(ocsps),
                new HashSet<>(certs)
        );
    }

    SignedDocuments aSignedDocuments(List<Signature> signatures) {
        return new SignedDocuments(
                signatures,
                Set.of(),
                Set.of(),
                Set.of()
        );
    }

    void assertContainsExactlyInAnyOrder(List<String> expected, List<String> actual) {
        assertEquals(new HashSet<>(expected), new HashSet<>(actual));
    }

}