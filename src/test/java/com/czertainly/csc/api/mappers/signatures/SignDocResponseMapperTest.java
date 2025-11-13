package com.czertainly.csc.api.mappers.signatures;

import com.czertainly.csc.api.signdoc.SignDocResponseDto;
import com.czertainly.csc.api.signdoc.ValidationInfo;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.model.DocumentSignature;
import com.czertainly.csc.model.Signatures;
import com.czertainly.csc.model.SignaturesWithValidationInfo;
import com.czertainly.csc.signing.configuration.SignaturePackaging;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static com.czertainly.csc.utils.assertions.CollectionAssertions.assertContainsExactlyInAnyOrder;
import static org.junit.jupiter.api.Assertions.*;

class SignDocResponseMapperTest {

    SignDocResponseMapper mapper = new SignDocResponseMapper();
    Base64.Encoder encoder = Base64.getEncoder();

    @Test
    void canMapRequest() {
        // given
        SignaturesWithValidationInfo<DocumentSignature> model = aSignedDocuments();

        // when
        Result<SignDocResponseDto, TextError> result = mapper.map(model);

        // then
        assertNotNull(result);
    }

    @Test
    void canMapValidationInfo() {
        // given
        Set<String> crls = Set.of("crl1", "crl2");
        Set<String> ocsps = Set.of("ocsp1", "ocsp2");
        Set<String> certs = Set.of("cert1", "cert2");
        SignaturesWithValidationInfo<DocumentSignature> model = aSignedDocuments(crls, ocsps, certs);

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
        List<DocumentSignature> signatures = List.of(
                new DocumentSignature("enveloped".getBytes(), SignaturePackaging.ENVELOPED),
                new DocumentSignature("detached".getBytes(), SignaturePackaging.DETACHED)
        );
        String encodedEnveloped = encoder.encodeToString("enveloped".getBytes());
        String encodedDetached = encoder.encodeToString("detached".getBytes());
        SignaturesWithValidationInfo<DocumentSignature> model = aSignedDocuments(signatures);

        // when
        Result<SignDocResponseDto, TextError> result = mapper.map(model);

        // then
        SignDocResponseDto response = result.unwrap();
        assertEquals(1, response.getDocumentWithSignature().size());
        assertEquals(encodedEnveloped, response.getDocumentWithSignature().getFirst());
        assertEquals(1, response.getSignatureObject().size());
        assertEquals(encodedDetached, response.getSignatureObject().getFirst());
    }

    @Test
    void signaturesAreBase64Encoded() {
        // given
        List<DocumentSignature> signatures = List.of(
                new DocumentSignature("enveloped".getBytes(), SignaturePackaging.ENVELOPED),
                new DocumentSignature("detached".getBytes(), SignaturePackaging.DETACHED)
        );
        String encodedEnveloped = encoder.encodeToString("enveloped".getBytes());
        String encodedDetached = encoder.encodeToString("detached".getBytes());
        SignaturesWithValidationInfo<DocumentSignature> model = aSignedDocuments(signatures);

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
        Set<String> crls = Set.of("crl1", "crl2");
        Set<String> ocsps = Set.of("ocsp1", "ocsp2");
        Set<String> certs = Set.of();
        SignaturesWithValidationInfo<DocumentSignature> model = aSignedDocuments(crls, ocsps, certs);

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
        Set<String> crls = Set.of("crl1", "crl2");
        Set<String> ocsps = Set.of();
        Set<String> certs = Set.of("cert1", "cert2");
        SignaturesWithValidationInfo<DocumentSignature> model = aSignedDocuments(crls, ocsps, certs);

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
        Set<String> crls = Set.of();
        Set<String> ocsps = Set.of("ocsp1", "ocsp2");
        Set<String> certs = Set.of("cert1", "cert2");
        SignaturesWithValidationInfo<DocumentSignature> model = aSignedDocuments(crls, ocsps, certs);

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
        Signatures<DocumentSignature> model = new Signatures<>( // Signatures container does not have validation info
                                                                List.of(
                                                                        new DocumentSignature(
                                                                                new byte[]{1, 2, 3},
                                                                                SignaturePackaging.ENVELOPED
                                                                        )
                                                                )
        );

        // when
        Result<SignDocResponseDto, TextError> result = mapper.map(model);

        // then
        assertNull(result.unwrap().getValidationInfo());
    }

    SignaturesWithValidationInfo<DocumentSignature> aSignedDocuments() {
        return new SignaturesWithValidationInfo<>(
                List.of(
                        new DocumentSignature(
                                new byte[]{1, 2, 3},
                                SignaturePackaging.ENVELOPED
                        ),
                        new DocumentSignature(
                                new byte[]{4, 5, 6},
                                SignaturePackaging.DETACHED
                        )
                ),
                Set.of("crl1", "crl2"),
                Set.of("ocsp1", "ocsp2"),
                Set.of("cert1", "cert2")
        );
    }

    SignaturesWithValidationInfo<DocumentSignature> aSignedDocuments(Set<String> crls, Set<String> ocsps,
                                                                     Set<String> certs
    ) {
        return new SignaturesWithValidationInfo<>(
                List.of(
                        new DocumentSignature(
                                new byte[]{1, 2, 3},
                                SignaturePackaging.ENVELOPED
                        ),
                        new DocumentSignature(
                                new byte[]{4, 5, 6},
                                SignaturePackaging.DETACHED
                        )
                ),
                new HashSet<>(crls),
                new HashSet<>(ocsps),
                new HashSet<>(certs)
        );
    }

    SignaturesWithValidationInfo<DocumentSignature> aSignedDocuments(List<DocumentSignature> signatures) {
        return new SignaturesWithValidationInfo<>(
                signatures,
                Set.of(),
                Set.of(),
                Set.of()
        );
    }

}