package com.czertainly.csc.api.mappers.signatures;

import com.czertainly.csc.api.BaseSignatureRequestDto;
import com.czertainly.csc.api.OperationMode;
import com.czertainly.csc.api.auth.SADParser;
import com.czertainly.csc.api.auth.SignatureActivationData;
import com.czertainly.csc.api.auth.TokenValidator;
import com.czertainly.csc.api.mappers.StructuredClientDataMapper;
import com.czertainly.csc.api.signdoc.AttributeDto;
import com.czertainly.csc.api.signdoc.DocumentDigestsDto;
import com.czertainly.csc.api.signdoc.DocumentDto;
import com.czertainly.csc.api.signdoc.SignDocRequestDto;
import com.czertainly.csc.common.exceptions.InvalidInputDataException;
import com.czertainly.csc.crypto.AlgorithmHelper;
import com.czertainly.csc.crypto.AlgorithmUnifier;
import com.czertainly.csc.signing.configuration.ConformanceLevel;
import com.czertainly.csc.signing.configuration.SignatureFormat;
import com.czertainly.csc.signing.configuration.SignaturePackaging;
import com.czertainly.csc.utils.jwt.TestIdp;
import com.czertainly.csc.utils.jwt.TestJWTs;
import org.instancio.Instancio;
import org.instancio.InstancioApi;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

import static org.instancio.Select.field;
import static org.junit.jupiter.api.Assertions.*;

class SignDocValidatingRequestMapperTest {

    AlgorithmHelper algorithmHelper = new AlgorithmHelper();
    AlgorithmUnifier algorithmUnifier = new AlgorithmUnifier(algorithmHelper);
    TokenValidator tokenValidator = TestIdp.defaultTokenValidator;
    Jackson2ObjectMapperBuilder objectMapperBuilder = new Jackson2ObjectMapperBuilder();
    StructuredClientDataMapper structuredClientDataMapper = new StructuredClientDataMapper(objectMapperBuilder);

    SADParser sadParser = new SADParser(tokenValidator);
    SignDocValidatingRequestMapper signDocValidatingRequestMapper = new SignDocValidatingRequestMapper(
            algorithmUnifier, sadParser, structuredClientDataMapper
    );

    @Test
    void canMapRequest() {
        // given
        UUID credentialID = UUID.randomUUID();
        String signatureQualifier = "eu_eidas_qes";
        String SAD = null;
        List<DocumentDto> documents = aDocumentsToSign();
        List<DocumentDigestsDto> documentDigests = null;
        OperationMode operationMode = OperationMode.SYNCHRONOUS;

        String clientData = "aClientData";
        Boolean returnValidationInfo = false;

        var dto = new SignDocRequestDto(
                credentialID.toString(),
                signatureQualifier,
                SAD,
                documents,
                documentDigests,
                operationMode.getValue(),
                0,
                null,
                clientData,
                returnValidationInfo
        );
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        var result = signDocValidatingRequestMapper.map(dto, sad);

        // then
        assertNotNull(result);
        assertEquals(credentialID, result.credentialID());
        assertEquals(signatureQualifier, result.signatureQualifier());
        assertEquals(OperationMode.SYNCHRONOUS, result.operationMode());
        assertEquals(clientData, result.clientData().get());
        assertEquals(returnValidationInfo, result.returnValidationInfo());
    }

    @Test
    void throwsIfNoDataProvidedToTheRequest() {
        // given
        SignDocRequestDto dto = null;
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        Executable ex = () -> signDocValidatingRequestMapper.map(dto, sad);

        // then
        Throwable t = assertThrows(InvalidInputDataException.class, ex);
        assertEquals("Missing request parameters.", t.getMessage());
    }


    // Test cases for CredentialID and SignatureQualifier

    @Test
    void throwsGivenNoCredentialIdAndSignatureQualifierProvided() {
        // given
        var dto = aDto()
                .set(field(SignDocRequestDto::getCredentialID), null)
                .set(field(SignDocRequestDto::getSignatureQualifier), null)
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        Executable ex = () -> signDocValidatingRequestMapper.map(dto, sad);

        // then
        Throwable t = assertThrows(InvalidInputDataException.class, ex);
        assertEquals("Empty credentialID and signatureQualifier. At least one of them must be provided.",
                     t.getMessage()
        );
    }

    @Test
    void mapsRequestGivenBothCredentialIDAndSignatureQualifierProvided() {
        // given
        UUID credentialID = UUID.randomUUID();
        var dto = aDto()
                .set(field(SignDocRequestDto::getCredentialID), credentialID.toString())
                .set(field(SignDocRequestDto::getSignatureQualifier), "eu_eidas_qes")
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        var result = signDocValidatingRequestMapper.map(dto, sad);

        // then
        assertEquals(credentialID, result.credentialID());
        assertEquals("eu_eidas_qes", result.signatureQualifier());
    }

    @Test
    void mapsRequestGivenOnlyCredentialIDProvided() {
        // given
        UUID credentialID = UUID.randomUUID();
        var dto = aDto()
                .set(field(SignDocRequestDto::getCredentialID), credentialID.toString())
                .set(field(SignDocRequestDto::getSignatureQualifier), null)
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        var result = signDocValidatingRequestMapper.map(dto, sad);

        // then
        assertEquals(credentialID, result.credentialID());
        assertNull(result.signatureQualifier());
    }

    @Test
    void mapsRequestGivenOnlySignatureQualifierProvided() {
        // given
        var dto = aDto()
                .set(field(SignDocRequestDto::getCredentialID), null)
                .set(field(SignDocRequestDto::getSignatureQualifier), "eu_eidas_qes")
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        var result = signDocValidatingRequestMapper.map(dto, sad);

        // then
        assertNull(result.credentialID());
        assertEquals("eu_eidas_qes", result.signatureQualifier());
    }


    // Test cases for SAD

    @Test
    void throwsGivenSadNotProvidedInTokenOrSeparately() {
        // given
        var dto = aDto()
                .set(field(BaseSignatureRequestDto.class, "SAD"), null)
                .create();
        SignatureActivationData sad = null;

        // when
        Executable ex = () -> signDocValidatingRequestMapper.map(dto, sad);

        // then
        Throwable t = assertThrows(InvalidInputDataException.class, ex);
        assertEquals("Missing (or invalid type) string parameter SAD", t.getMessage());
    }

    @Test
    void throwsGivenSadProvidedInTokenAndAlsoSeparately() {
        // given
        var sadJwt = TestIdp.credentialToken();
        var sad = TestJWTs.toSad(sadJwt);
        var dto = aDto()
                .set(field(BaseSignatureRequestDto.class, "SAD"), sadJwt.getTokenValue())
                .create();

        // when
        Executable ex = () -> signDocValidatingRequestMapper.map(dto, sad);

        // then
        Throwable t = assertThrows(InvalidInputDataException.class, ex);
        assertEquals("Signature activation data was provided in both the request" +
                             " and the access token. Please provide it only at one place.",
                     t.getMessage()
        );
    }

    @Test
    void sadIsMappedGivenItWasProvidedSeparately() {
        // given
        var dto = aDto().create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        var result = signDocValidatingRequestMapper.map(dto, sad);

        // then
        assertEquals(sad, result.sad());
    }

    @Test
    void sadIsMappedGivenItWasProvidedThroughToken() {
        // given
        var sadJwt = TestIdp.credentialToken();
        var dto = aDto()
                .set(field(BaseSignatureRequestDto.class, "SAD"), sadJwt.getTokenValue())
                .create();

        // when
        var result = signDocValidatingRequestMapper.map(dto, null);

        // then
        var sad = TestJWTs.toSad(sadJwt);
        var mappedSad = result.sad();
        assertEquals(sad.getUserID(), mappedSad.getUserID());
        assertEquals(sad.getCredentialID(), mappedSad.getCredentialID());
        assertEquals(sad.getSignatureQualifier(), mappedSad.getSignatureQualifier());
        assertEquals(sad.getHashAlgorithmOID(), mappedSad.getHashAlgorithmOID());
        assertEquals(sad.getNumSignatures(), mappedSad.getNumSignatures());
        assertEquals(sad.getHashes(), mappedSad.getHashes());
        assertEquals(sad.getClientData(), mappedSad.getClientData());
    }

    @Test
    void throwsGivenSadProvidedInTokenIsNotValid() {
        // given
        var dto = aDto()
                .set(field(BaseSignatureRequestDto.class, "SAD"), "invalid")
                .create();

        // when
        Executable ex = () -> signDocValidatingRequestMapper.map(dto, null);

        // then
        Throwable t = assertThrows(InvalidInputDataException.class, ex);
        assertTrue(t.getMessage().contains("Failed to validate SAD"));
    }

    // Test Cases for Documents and Document Digests presence

    @Test
    void throwsGivenBothDocumentsToSignAndDocumentDigestsToSignArePresent() {
        // given
        var dto = aDto()
                .set(field(SignDocRequestDto::getDocumentDigests), aDocumentDigestsToSign())
                .set(field(SignDocRequestDto::getDocuments), aDocumentsToSign())
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        Executable ex = () -> signDocValidatingRequestMapper.map(dto, sad);

        // then
        Throwable t = assertThrows(InvalidInputDataException.class, ex);
        assertEquals("Cannot provide both documentDigests and documents parameters simultaneously.", t.getMessage());
    }

    @Test
    void throwsGivenNoneOfDocumentsToSignAndDocumentDigestsToSignArePresent() {
        // given
        var dto = aDto()
                .set(field(SignDocRequestDto::getDocumentDigests), List.of())
                .set(field(SignDocRequestDto::getDocuments), List.of())
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        Executable ex = () -> signDocValidatingRequestMapper.map(dto, sad);

        // then
        Throwable t = assertThrows(InvalidInputDataException.class, ex);
        assertEquals("Either documentDigests or documents must be present in the request.", t.getMessage());
    }


    // Test Cases for Operation Mode

    @Test
    void throwsGivenOperationModeNotKnown() {
        // given
        var dto = aDto()
                .set(field(SignDocRequestDto::getOperationMode), "not-known")
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        Executable ex = () -> signDocValidatingRequestMapper.map(dto, sad);

        // then
        Throwable t = assertThrows(InvalidInputDataException.class, ex);
        assertEquals("Invalid parameter operationMode.", t.getMessage());
    }

    @Test
    void operationModeDefaultsToSynchronousWhenNotSpecified() {
        // given
        var dto = aDto()
                .set(field(SignDocRequestDto::getOperationMode), null)
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        var result = signDocValidatingRequestMapper.map(dto, sad);

        // then
        assertEquals(OperationMode.SYNCHRONOUS, result.operationMode());
    }


    // Test Cases for Validation Info

    @Test
    void returnValidationInfoDefaultsToFalseWhenNotSpecified() {
        // given
        var dto = aDto()
                .set(field(SignDocRequestDto::getReturnValidationInfo), null)
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        var result = signDocValidatingRequestMapper.map(dto, sad);

        // then
        assertFalse(result.returnValidationInfo());
    }


    // Test Cases for Documents mapping

    @Test
    void mapsDocumentsToSign() {
        // given
        var documentContent = Base64.getEncoder().encodeToString("{ \"hello\": \"world\" }".getBytes());
        List<DocumentDto> documents = List.of(
                new DocumentDto(
                        documentContent,
                        "J",
                        "Ades-B-T",
                        "1.2.840.113549.1.1.11", // SHA256WithRSA
                        "signAlgoParams",
                        List.of(new AttributeDto("attr1", "val1")),
                        "Attached"
                )
        );
        var dto = aDto()
                .set(field(SignDocRequestDto::getDocuments), documents)
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        var result = signDocValidatingRequestMapper.map(dto, sad);

        // then
        assertEquals(1, result.documentsToSign().size());
        var parsedDoc = result.documentsToSign().getFirst();

        assertEquals(documentContent, parsedDoc.content());
        assertEquals(SignatureFormat.JAdEs, parsedDoc.signatureFormat());
        assertEquals(ConformanceLevel.AdES_B_T, parsedDoc.conformanceLevel());
        assertEquals("RSA", parsedDoc.keyAlgorithm());
        assertEquals("SHA256", parsedDoc.digestAlgorithm());
        assertEquals("signAlgoParams", parsedDoc.signAlgoParams());
        assertEquals(SignaturePackaging.ATTACHED, parsedDoc.signaturePackaging());
        // Not Yet Implemented
        //        assertEquals(1, parsedDoc.signedAttributes().size());
        //        assertEquals("val1", parsedDoc.signedAttributes().get("attr1"));

    }

    @ParameterizedTest
    @MethodSource("getSignatureFormats")
    void canMapAllSignatureFormatsForDocumentsToSign(SignatureFormat format, String formatStringValue) {
        // given
        var documents = List.of(
                aDocumentToSign()
                        .set(field(DocumentDto::getSignatureFormat), formatStringValue)
                        .create()
        );
        var dto = aDto()
                .set(field(SignDocRequestDto::getDocuments), documents)
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        var result = signDocValidatingRequestMapper.map(dto, sad);

        // then
        var parsedDoc = result.documentsToSign().getFirst();
        assertEquals(format, parsedDoc.signatureFormat());
    }

    @Test
    void throwsGivenSignatureFormatIsNotKnownForDocumentsToSign() {
        // given
        var documents = List.of(
                aDocumentToSign()
                        .set(field(DocumentDto::getSignatureFormat), "not-known")
                        .create()
        );
        var dto = aDto()
                .set(field(SignDocRequestDto::getDocuments), documents)
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        Executable ex = () -> signDocValidatingRequestMapper.map(dto, sad);

        // then
        Throwable t = assertThrows(InvalidInputDataException.class, ex);
        assertEquals("Invalid parameter signature_format.", t.getMessage());
    }

    @Test
    void throwsGivenSignatureFormatNotProvidedForDocumentsToSign() {
        // given
        var documents = List.of(
                aDocumentToSign()
                        .set(field(DocumentDto::getSignatureFormat), null)
                        .create()
        );
        var dto = aDto()
                .set(field(SignDocRequestDto::getDocuments), documents)
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        Executable ex = () -> signDocValidatingRequestMapper.map(dto, sad);

        // then
        Throwable t = assertThrows(InvalidInputDataException.class, ex);
        assertEquals("Missing string parameter signature_format", t.getMessage());
    }


    @ParameterizedTest
    @MethodSource("getConformanceLevels")
    void canMapAllConformanceLevelsWithDefaultWhenMissingForDocumentsToSign(ConformanceLevel level,
                                                                            String levelStringValue
    ) {
        // given
        var documents = List.of(
                aDocumentToSign()
                        .set(field(DocumentDto::getConformanceLevel), levelStringValue)
                        .create()
        );
        var dto = aDto()
                .set(field(SignDocRequestDto::getDocuments), documents)
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        var result = signDocValidatingRequestMapper.map(dto, sad);

        // then
        var parsedDoc = result.documentsToSign().getFirst();
        assertEquals(level, parsedDoc.conformanceLevel());
    }

    @Test
    void throwsGivenConformanceLevelIsNotKnownForDocumentsToSign() {
        // given
        var documents = List.of(
                aDocumentToSign()
                        .set(field(DocumentDto::getConformanceLevel), "not-known")
                        .create()
        );
        var dto = aDto()
                .set(field(SignDocRequestDto::getDocuments), documents)
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        Executable ex = () -> signDocValidatingRequestMapper.map(dto, sad);

        // then
        Throwable t = assertThrows(InvalidInputDataException.class, ex);
        assertEquals("Invalid parameter conformance_level.", t.getMessage());
    }

    @ParameterizedTest
    @MethodSource("getSignaturePackagings")
    void canMapAllSignaturePackagingsForDocumentsToSign(SignaturePackaging packaging, String packagingStringValue) {
        // given
        var documents = List.of(
                aDocumentToSign()
                        .set(field(DocumentDto::getSignaturePackaging), packagingStringValue)
                        .create()
        );
        var dto = aDto()
                .set(field(SignDocRequestDto::getDocuments), documents)
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        var result = signDocValidatingRequestMapper.map(dto, sad);

        // then
        var parsedDoc = result.documentsToSign().getFirst();
        assertEquals(packaging, parsedDoc.signaturePackaging());
    }

    @Test
    void throwsGivenSignaturePackagingNotKnownForDocumentsToSign() {
        // given
        var documents = List.of(
                aDocumentToSign()
                        .set(field(DocumentDto::getSignaturePackaging), "not-known")
                        .create()
        );
        var dto = aDto()
                .set(field(SignDocRequestDto::getDocuments), documents)
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        Executable ex = () -> signDocValidatingRequestMapper.map(dto, sad);

        // then
        Throwable t = assertThrows(InvalidInputDataException.class, ex);
        assertEquals("Invalid parameter signed_envelope_property", t.getMessage());
    }

    @ParameterizedTest
    @MethodSource("defaultSignaturePackagings")
    void setsCorrectDefaultPackagingBasedOnFormatGivenSignaturePackagingNotProvidedForDocumentsToSign(
            SignaturePackaging packaging, String signatureFormatString
    ) {
        // given
        var documents = List.of(
                aDocumentToSign()
                        .set(field(DocumentDto::getSignatureFormat), signatureFormatString)
                        .set(field(DocumentDto::getSignaturePackaging), null)
                        .create()
        );
        var dto = aDto()
                .set(field(SignDocRequestDto::getDocuments), documents)
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        var result = signDocValidatingRequestMapper.map(dto, sad);

        // then
        var parsedDoc = result.documentsToSign().getFirst();
        assertEquals(packaging, parsedDoc.signaturePackaging());
    }


    // Test Cases for Document Digests mapping
    @Test
    void mapsDocumentDigestsToSign() {
        // given
        var hashes = List.of("hash1", "hash2");
        var documentDigests = List.of(
                new DocumentDigestsDto(
                        hashes,
                        "2.16.840.1.101.3.4.2.1", // SHA256
                        "J",
                        "Ades-B-T",
                        "1.2.840.113549.1.1.11", // SHA256WithRSA
                        "signAlgoParams",
                        List.of(new AttributeDto("attr1", "val1")),
                        "Attached"
                )
        );
        var dto = aDto()
                .set(field(SignDocRequestDto::getDocumentDigests), documentDigests)
                .set(field(SignDocRequestDto::getDocuments), List.of())
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        var result = signDocValidatingRequestMapper.map(dto, sad);

        // then
        assertEquals(1, result.documentDigestsToSign().size());
        var parsedDigestsToSign = result.documentDigestsToSign().getFirst();
        assertEquals(hashes, parsedDigestsToSign.hashes());
        assertEquals("SHA256", parsedDigestsToSign.digestAlgorithm());
        assertEquals(SignatureFormat.JAdEs, parsedDigestsToSign.signatureFormat());
        assertEquals(ConformanceLevel.AdES_B_T, parsedDigestsToSign.conformanceLevel());
        assertEquals("RSA", parsedDigestsToSign.keyAlgorithm());
        assertEquals("signAlgoParams", parsedDigestsToSign.signAlgoParams());
        assertEquals(SignaturePackaging.ATTACHED, parsedDigestsToSign.signaturePackaging());
    }

    @ParameterizedTest
    @MethodSource("getSignatureFormats")
    void canMapAllSignatureFormatsForDocumentDigestsToSign(SignatureFormat format, String formatStringValue) {
        // given
        var documentDigests = List.of(
                aDocumentDigestToSign()
                        .set(field(DocumentDto::getSignatureFormat), formatStringValue)
                        .create()
        );
        var dto = aDto()
                .set(field(SignDocRequestDto::getDocumentDigests), documentDigests)
                .set(field(SignDocRequestDto::getDocuments), List.of())
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        var result = signDocValidatingRequestMapper.map(dto, sad);

        // then
        var parseDigests = result.documentDigestsToSign().getFirst();
        assertEquals(format, parseDigests.signatureFormat());
    }

    @Test
    void throwsGivenSignatureFormatIsNotKnownForDocumentDigestsToSign() {
        // given
        var documentDigests = List.of(
                aDocumentDigestToSign()
                        .set(field(DocumentDto::getSignatureFormat), "not-known")
                        .create()
        );
        var dto = aDto()
                .set(field(SignDocRequestDto::getDocumentDigests), documentDigests)
                .set(field(SignDocRequestDto::getDocuments), List.of())
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        Executable ex = () -> signDocValidatingRequestMapper.map(dto, sad);

        // then
        Throwable t = assertThrows(InvalidInputDataException.class, ex);
        assertEquals("Invalid parameter signature_format.", t.getMessage());
    }

    @Test
    void throwsGivenSignatureFormatNotProvidedForDocumentDigestsToSign() {
        // given
        var documentDigests = List.of(
                aDocumentDigestToSign()
                        .set(field(DocumentDto::getSignatureFormat), null)
                        .create()
        );
        var dto = aDto()
                .set(field(SignDocRequestDto::getDocumentDigests), documentDigests)
                .set(field(SignDocRequestDto::getDocuments), List.of())
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        Executable ex = () -> signDocValidatingRequestMapper.map(dto, sad);

        // then
        Throwable t = assertThrows(InvalidInputDataException.class, ex);
        assertEquals("Missing string parameter signature_format", t.getMessage());
    }

    @ParameterizedTest
    @MethodSource("getConformanceLevels")
    void canMapAllConformanceLevelsWithDefaultWhenMissingForDocumentDigests(ConformanceLevel level,
                                                                            String levelStringValue
    ) {
        // given
        var documentDigests = List.of(
                aDocumentDigestToSign()
                        .set(field(DocumentDto::getConformanceLevel), levelStringValue)
                        .create()
        );
        var dto = aDto()
                .set(field(SignDocRequestDto::getDocumentDigests), documentDigests)
                .set(field(SignDocRequestDto::getDocuments), List.of())
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        var result = signDocValidatingRequestMapper.map(dto, sad);

        // then
        var parsedDigests = result.documentDigestsToSign().getFirst();
        assertEquals(level, parsedDigests.conformanceLevel());
    }


    @Test
    void throwsGivenConformanceLevelIsNotKnownForDocumentDigestsToSign() {
        // given
        var documentDigests = List.of(
                aDocumentDigestToSign()
                        .set(field(DocumentDto::getConformanceLevel), "not-known")
                        .create()
        );
        var dto = aDto()
                .set(field(SignDocRequestDto::getDocumentDigests), documentDigests)
                .set(field(SignDocRequestDto::getDocuments), List.of())
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        Executable ex = () -> signDocValidatingRequestMapper.map(dto, sad);

        // then
        Throwable t = assertThrows(InvalidInputDataException.class, ex);
        assertEquals("Invalid parameter conformance_level.", t.getMessage());
    }

    @ParameterizedTest
    @MethodSource("getSignaturePackagings")
    void canMapAllSignaturePackagingsForDocumentDigestsToSign(SignaturePackaging packaging,
                                                              String packagingStringValue
    ) {
        // given
        var documentDigests = List.of(
                aDocumentDigestToSign()
                        .set(field(DocumentDto::getSignaturePackaging), packagingStringValue)
                        .create()
        );
        var dto = aDto()
                .set(field(SignDocRequestDto::getDocumentDigests), documentDigests)
                .set(field(SignDocRequestDto::getDocuments), List.of())
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        var result = signDocValidatingRequestMapper.map(dto, sad);

        // then
        var parsedDocumentDigests = result.documentDigestsToSign().getFirst();
        assertEquals(packaging, parsedDocumentDigests.signaturePackaging());
    }

    @Test
    void throwsGivenSignaturePackagingNotKnownForDocumentDigests() {
        // given
        var documentDigests = List.of(
                aDocumentDigestToSign()
                        .set(field(DocumentDto::getSignaturePackaging), "not-known")
                        .create()
        );
        var dto = aDto()
                .set(field(SignDocRequestDto::getDocumentDigests), documentDigests)
                .set(field(SignDocRequestDto::getDocuments), List.of())
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        Executable ex = () -> signDocValidatingRequestMapper.map(dto, sad);

        // then
        Throwable t = assertThrows(InvalidInputDataException.class, ex);
        assertEquals("Invalid parameter signed_envelope_property", t.getMessage());
    }

    @ParameterizedTest
    @MethodSource("defaultSignaturePackagings")
    void setsCorrectDefaultPackagingBasedOnFormatGivenSignaturePackagingNotProvidedForDocumentDigests(
            SignaturePackaging packaging, String signatureFormatString
    ) {
        // given
        var documentDigests = List.of(
                aDocumentDigestToSign()
                        .set(field(DocumentDto::getSignatureFormat), signatureFormatString)
                        .set(field(DocumentDto::getSignaturePackaging), null)
                        .create()
        );
        var dto = aDto()
                .set(field(SignDocRequestDto::getDocumentDigests), documentDigests)
                .set(field(SignDocRequestDto::getDocuments), List.of())
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        var result = signDocValidatingRequestMapper.map(dto, sad);

        // then
        var parsedDocumentDigests = result.documentDigestsToSign().getFirst();
        assertEquals(packaging, parsedDocumentDigests.signaturePackaging());
    }

    // Helper methods

    private InstancioApi<SignDocRequestDto> aDto() {
        return Instancio.of(SignDocRequestDto.class)
                        .set(field(SignDocRequestDto::getCredentialID), UUID.randomUUID().toString())
                        .set(field(SignDocRequestDto::getSignatureQualifier), "eu_eidas_qes")
                        .set(field(SignDocRequestDto::getOperationMode), "S")
                        .set(field(SignDocRequestDto::getDocuments), aDocumentsToSign())
                        .set(field(SignDocRequestDto::getDocumentDigests), List.of())
                        .set(field(SignDocRequestDto::getDocumentDigests), List.of())
                        .set(field(BaseSignatureRequestDto.class, "SAD"), null);
    }


    List<DocumentDto> aDocumentsToSign() {
        String doc1Content = Base64.getEncoder().encodeToString("{ \"hello\": \"world\" }".getBytes());
        String doc2Content = Base64.getEncoder().encodeToString("{ \"hello\": \"world two\" }".getBytes());
        return List.of(
                new DocumentDto(
                        doc1Content,
                        "J",
                        "Ades-B-T",
                        "1.2.840.113549.1.1.11", // SHA256WithRSA
                        null,
                        null,
                        "Attached"
                ),
                new DocumentDto(
                        doc2Content,
                        "X",
                        "Ades-B-T",
                        "1.2.840.113549.1.1.11", // SHA256WithRSA
                        null,
                        null,
                        "Enveloped"
                )
        );
    }

    InstancioApi<DocumentDto> aDocumentToSign() {
        String doc1Content = Base64.getEncoder().encodeToString("{ \"hello\": \"world\" }".getBytes());
        return Instancio.of(DocumentDto.class)
                        .set(field(DocumentDto::getDocument), doc1Content)
                        .set(field(DocumentDto::getSignatureFormat), "J")
                        .set(field(DocumentDto::getConformanceLevel), "Ades-B-T")
                        .set(field(DocumentDto::getSignAlgo), "1.2.840.113549.1.1.11")
                        .set(field(DocumentDto::getSignAlgoParams), null)
                        .set(field(DocumentDto::getSignedAttributes), null)
                        .set(field(DocumentDto::getSignaturePackaging), "Attached");
    }

    InstancioApi<DocumentDigestsDto> aDocumentDigestToSign() {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String hashe = Base64.getEncoder().encodeToString(digest.digest("{ \"hello\": \"world\" }".getBytes()));
            var hashes = List.of(hashe);

            return Instancio.of(DocumentDigestsDto.class)
                            .set(field(DocumentDigestsDto::getHashes), hashes)
                            .set(field(DocumentDigestsDto::getHashAlgorithmOID), "2.16.840.1.101.3.4.2.1")
                            .set(field(DocumentDigestsDto::getSignatureFormat), "J")
                            .set(field(DocumentDigestsDto::getConformanceLevel), "Ades-B-T")
                            .set(field(DocumentDigestsDto::getSignAlgo), "1.2.840.113549.1.1.11")
                            .set(field(DocumentDigestsDto::getSignAlgoParams), null)
                            .set(field(DocumentDigestsDto::getSignedAttributes), null)
                            .set(field(DocumentDigestsDto::getSignaturePackaging), "Attached");
        } catch (NoSuchAlgorithmException e) {
            fail("SHA-256 algorithm not found");
            return null;
        }
    }

    List<DocumentDigestsDto> aDocumentDigestsToSign() {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            String doc1 = "{ \"hello\": \"world\" }";
            String doc2 = "{ \"hello\": \"world two\" }";
            String doc1Digest = Base64.getEncoder().encodeToString(digest.digest(doc1.getBytes()));
            String doc2Digest = Base64.getEncoder().encodeToString(digest.digest(doc2.getBytes()));
            return List.of(
                    new DocumentDigestsDto(
                            List.of(doc1Digest),
                            "2.16.840.1.101.3.4.2.1", // SHA-256
                            "J",
                            "Ades-B-T",
                            "1.2.840.113549.1.1.11", // SHA256WithRSA
                            null,
                            null,
                            "Attached"
                    ),
                    new DocumentDigestsDto(
                            List.of(doc2Digest),
                            "2.16.840.1.101.3.4.2.1", // SHA-256
                            "X",
                            "Ades-B-T",
                            "1.2.840.113549.1.1.11", // SHA256WithRSA
                            null,
                            null,
                            "Enveloped"
                    )
            );
        } catch (NoSuchAlgorithmException e) {
            fail("SHA-256 algorithm not found");
            return null;
        }
    }

    static Stream<Arguments> getSignatureFormats() {
        return Stream.of(
                Arguments.of(SignatureFormat.JAdEs, "J"),
                Arguments.of(SignatureFormat.CAdES, "C"),
                Arguments.of(SignatureFormat.XAdES, "X"),
                Arguments.of(SignatureFormat.PAdES, "P")
        );
    }

    static Stream<Arguments> getSignaturePackagings() {
        return Stream.of(
                Arguments.of(SignaturePackaging.ATTACHED, "Attached"),
                Arguments.of(SignaturePackaging.DETACHED, "Detached"),
                Arguments.of(SignaturePackaging.ENVELOPING, "Enveloping"),
                Arguments.of(SignaturePackaging.ENVELOPED, "Enveloped"),
                Arguments.of(SignaturePackaging.REVISION, "Revision"),
                Arguments.of(SignaturePackaging.CERTIFICATION, "Certification"),
                Arguments.of(SignaturePackaging.PARALLEL, "Parallel")
        );
    }

    static Stream<Arguments> getConformanceLevels() {
        return Stream.of(
                Arguments.of(ConformanceLevel.AdES_B_B, "Ades-B-B"),
                Arguments.of(ConformanceLevel.AdES_B_T, "Ades-B-T"),
                Arguments.of(ConformanceLevel.AdES_B_LT, "Ades-B-LT"),
                Arguments.of(ConformanceLevel.AdES_B_LTA, "Ades-B-LTA"),
                Arguments.of(ConformanceLevel.AdES_B, "Ades-B"),
                Arguments.of(ConformanceLevel.AdES_T, "Ades-T"),
                Arguments.of(ConformanceLevel.AdES_LT, "Ades-LT"),
                Arguments.of(ConformanceLevel.AdES_LTA, "Ades-LTA"),
                Arguments.of(ConformanceLevel.AdES_B_B, null)
        );
    }

    static Stream<Arguments> defaultSignaturePackagings() {
        return Stream.of(
                Arguments.of(SignaturePackaging.ATTACHED, "C"),
                Arguments.of(SignaturePackaging.CERTIFICATION, "P"),
                Arguments.of(SignaturePackaging.ENVELOPED, "X"),
                Arguments.of(SignaturePackaging.ATTACHED, "J")
        );
    }
}