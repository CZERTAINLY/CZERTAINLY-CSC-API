package com.czertainly.csc.api.mappers.signatures;

import com.czertainly.csc.api.BaseSignatureRequestDto;
import com.czertainly.csc.api.OperationMode;
import com.czertainly.csc.api.auth.SADParser;
import com.czertainly.csc.api.auth.SignatureActivationData;
import com.czertainly.csc.api.auth.TokenValidator;
import com.czertainly.csc.api.signhash.SignHashRequestDto;
import com.czertainly.csc.common.exceptions.InvalidInputDataException;
import com.czertainly.csc.crypto.AlgorithmHelper;
import com.czertainly.csc.crypto.AlgorithmUnifier;
import com.czertainly.csc.utils.jwt.TestIdp;
import com.czertainly.csc.utils.jwt.TestJWTs;
import org.instancio.Instancio;
import org.instancio.InstancioApi;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static org.instancio.Select.field;
import static org.junit.jupiter.api.Assertions.*;

class SignHashValidatingRequestMapperTest {

    AlgorithmHelper algorithmHelper = new AlgorithmHelper();
    AlgorithmUnifier algorithmUnifier = new AlgorithmUnifier(algorithmHelper);
    TokenValidator tokenValidator = TestIdp.defaultTokenValidator;
    SADParser sadParser = new SADParser(tokenValidator);
    SignHashValidatingRequestMapper mapper = new SignHashValidatingRequestMapper(algorithmUnifier, sadParser);

    @Test
    void canMapRequest() {
        // given
        UUID credentialID = UUID.randomUUID();
        String SAD = null;
        List<String> hashes = List.of(
                Base64.getEncoder().encodeToString("hash1".getBytes()),
                Base64.getEncoder().encodeToString("hash2".getBytes())
        );
        String signAlgo = "1.2.840.113549.1.1.11"; // SHA256WithRSA
        String operationMode = "S";
        String clientData = "aClientData";

        var dto = new SignHashRequestDto(
                credentialID.toString(),
                SAD,
                hashes,
                null,
                signAlgo,
                null,
                operationMode,
                0,
                null,
                clientData
        );
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        var result = mapper.map(dto, sad);

        // then
        assertNotNull(result);
        assertEquals(credentialID, result.credentialID());
        assertEquals(hashes, result.hashes());
        assertEquals("RSA", result.keyAlgo());
        assertEquals("SHA256", result.digestAlgo());
        assertEquals(OperationMode.SYNCHRONOUS, result.operationMode());
        assertEquals(clientData, result.clientData());
    }

    @Test
    void throwsIfNoDataProvidedToTheRequest() {
        // given
        SignHashRequestDto dto = null;
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        Executable ex = () -> mapper.map(dto, sad);

        // then
        Throwable t = assertThrows(InvalidInputDataException.class, ex);
        assertEquals("Missing request parameters.", t.getMessage());
    }

    @Test
    void throwsGivenEmptyCredentialID() {
        // given
        var dto = aDto()
                .set(field(SignHashRequestDto::getCredentialID), "")
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        Executable ex = () -> mapper.map(dto, sad);

        // then
        Throwable t = assertThrows(InvalidInputDataException.class, ex);
        // Empty string fails UUID parsing, not the isEmpty() check
        assertEquals("Invalid string parameter credentialID", t.getMessage());
    }

    @Test
    void throwsGivenInvalidCredentialIDFormat() {
        // given
        var dto = aDto()
                .set(field(SignHashRequestDto::getCredentialID), "not-a-valid-uuid")
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        Executable ex = () -> mapper.map(dto, sad);

        // then
        Throwable t = assertThrows(InvalidInputDataException.class, ex);
        assertEquals("Invalid string parameter credentialID", t.getMessage());
    }

    @Test
    void mapsValidCredentialID() {
        // given
        UUID credentialID = UUID.randomUUID();
        var dto = aDto()
                .set(field(SignHashRequestDto::getCredentialID), credentialID.toString())
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        var result = mapper.map(dto, sad);

        // then
        assertEquals(credentialID, result.credentialID());
    }

    @Test
    void throwsGivenSadNotProvidedInTokenOrSeparately() {
        // given
        var dto = aDto()
                .set(field(BaseSignatureRequestDto.class, "SAD"), null)
                .create();
        SignatureActivationData sad = null;

        // when
        Executable ex = () -> mapper.map(dto, sad);

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
        Executable ex = () -> mapper.map(dto, sad);

        // then
        Throwable t = assertThrows(InvalidInputDataException.class, ex);
        assertTrue(t.getMessage().contains("Signature activation data was provided in both the request" +
                                                   " and the access token"));
    }

    @Test
    void sadIsMappedGivenItWasProvidedSeparately() {
        // given
        var dto = aDto().create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        var result = mapper.map(dto, sad);

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
        var result = mapper.map(dto, null);

        // then
        var sad = TestJWTs.toSad(sadJwt);
        var mappedSad = result.sad();
        assertEquals(sad.getUserID(), mappedSad.getUserID());
    }

    @Test
    void throwsGivenSadProvidedInTokenIsNotValid() {
        // given
        var dto = aDto()
                .set(field(BaseSignatureRequestDto.class, "SAD"), "invalid")
                .create();

        // when
        Executable ex = () -> mapper.map(dto, null);

        // then
        Throwable t = assertThrows(InvalidInputDataException.class, ex);
        assertTrue(t.getMessage().contains("Failed to validate SAD"));
    }

    @Test
    void throwsGivenHashesNotProvided() {
        // given
        var dto = aDto()
                .set(field(SignHashRequestDto::getHashes), null)
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        Executable ex = () -> mapper.map(dto, sad);

        // then
        Throwable t = assertThrows(InvalidInputDataException.class, ex);
        assertEquals("Missing (or invalid type) string parameter credentialID.", t.getMessage());
    }

    @Test
    void mapsHashesCorrectly() {
        // given
        List<String> hashes = List.of(
                Base64.getEncoder().encodeToString("hash1".getBytes()),
                Base64.getEncoder().encodeToString("hash2".getBytes()),
                Base64.getEncoder().encodeToString("hash3".getBytes())
        );
        var dto = aDto()
                .set(field(SignHashRequestDto::getHashes), hashes)
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        var result = mapper.map(dto, sad);

        // then
        assertEquals(hashes, result.hashes());
        assertEquals(3, result.hashes().size());
    }

    @Test
    void mapsSingleHash() {
        // given
        List<String> hashes = List.of(Base64.getEncoder().encodeToString("single-hash".getBytes()));
        var dto = aDto()
                .set(field(SignHashRequestDto::getHashes), hashes)
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        var result = mapper.map(dto, sad);

        // then
        assertEquals(1, result.hashes().size());
        assertEquals(hashes.get(0), result.hashes().get(0));
    }

    @Test
    void mapsSignAlgoCorrectly() {
        // given
        var dto = aDto()
                .set(field(SignHashRequestDto::getSignAlgo), "1.2.840.113549.1.1.11") // SHA256WithRSA
                .set(field(SignHashRequestDto::getHashAlgorithmOID), null)
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        var result = mapper.map(dto, sad);

        // then
        assertEquals("RSA", result.keyAlgo());
        assertEquals("SHA256", result.digestAlgo());
    }

    @Test
    void mapsSignAlgoWithHashAlgorithmOID() {
        // given
        var dto = aDto()
                .set(field(SignHashRequestDto::getSignAlgo), "1.2.840.113549.1.1.1") // RSA
                .set(field(SignHashRequestDto::getHashAlgorithmOID), "2.16.840.1.101.3.4.2.1") // SHA256
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        var result = mapper.map(dto, sad);

        // then
        assertEquals("RSA", result.keyAlgo());
        assertEquals("SHA256", result.digestAlgo());
    }

    @Test
    void throwsGivenInvalidSignAlgo() {
        // given
        var dto = aDto()
                .set(field(SignHashRequestDto::getSignAlgo), "invalid-oid")
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        Executable ex = () -> mapper.map(dto, sad);

        // then
        assertThrows(InvalidInputDataException.class, ex);
    }

    @Test
    void mapsECDSAAlgorithm() {
        // given
        var dto = aDto()
                .set(field(SignHashRequestDto::getSignAlgo), "1.2.840.10045.4.3.2") // SHA256withECDSA
                .set(field(SignHashRequestDto::getHashAlgorithmOID), null)
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        var result = mapper.map(dto, sad);

        // then
        assertEquals("ECDSA", result.keyAlgo());
        assertEquals("SHA256", result.digestAlgo());
    }

    @Test
    void throwsGivenOperationModeNotKnown() {
        // given
        var dto = aDto()
                .set(field(SignHashRequestDto::getOperationMode), "not-known")
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        Executable ex = () -> mapper.map(dto, sad);

        // then
        Throwable t = assertThrows(InvalidInputDataException.class, ex);
        assertEquals("Invalid parameter operationMode.", t.getMessage());
    }

    @Test
    void operationModeDefaultsToSynchronousWhenNotSpecified() {
        // given
        var dto = aDto()
                .set(field(SignHashRequestDto::getOperationMode), null)
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        var result = mapper.map(dto, sad);

        // then
        assertEquals(OperationMode.SYNCHRONOUS, result.operationMode());
    }

    @Test
    void mapsSynchronousOperationMode() {
        // given
        var dto = aDto()
                .set(field(SignHashRequestDto::getOperationMode), "S")
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        var result = mapper.map(dto, sad);

        // then
        assertEquals(OperationMode.SYNCHRONOUS, result.operationMode());
    }

    @Test
    void mapsAsynchronousOperationMode() {
        // given
        var dto = aDto()
                .set(field(SignHashRequestDto::getOperationMode), "A")
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        var result = mapper.map(dto, sad);

        // then
        assertEquals(OperationMode.ASYNCHRONOUS, result.operationMode());
    }

    @Test
    void mapsClientDataWhenProvided() {
        // given
        String clientData = "custom-client-data";
        var dto = aDto()
                .set(field(SignHashRequestDto::getClientData), clientData)
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        var result = mapper.map(dto, sad);

        // then
        assertEquals(clientData, result.clientData());
    }

    @Test
    void clientDataDefaultsToEmptyStringWhenNotProvided() {
        // given
        var dto = aDto()
                .set(field(SignHashRequestDto::getClientData), null)
                .create();
        var sad = TestJWTs.toSad(TestIdp.credentialToken());

        // when
        var result = mapper.map(dto, sad);

        // then
        assertEquals("", result.clientData());
    }

    @Test
    void mapsCompleteRequestWithAllFields() {
        // given
        UUID credentialID = UUID.randomUUID();
        List<String> hashes = List.of(
                Base64.getEncoder().encodeToString("hash1".getBytes()),
                Base64.getEncoder().encodeToString("hash2".getBytes())
        );
        String signAlgo = "1.2.840.113549.1.1.11"; // SHA256WithRSA
        String clientData = "integration-test-data";

        var sadJwt = TestIdp.credentialToken();
        var dto = new SignHashRequestDto(
                credentialID.toString(),
                sadJwt.getTokenValue(),
                hashes,
                null,
                signAlgo,
                null,
                "S",
                0,
                null,
                clientData
        );

        // when
        var result = mapper.map(dto, null);

        // then
        assertNotNull(result);
        assertEquals(credentialID, result.credentialID());
        assertEquals(hashes, result.hashes());
        assertEquals("RSA", result.keyAlgo());
        assertEquals("SHA256", result.digestAlgo());
        assertEquals(OperationMode.SYNCHRONOUS, result.operationMode());
        assertEquals(clientData, result.clientData());
        assertNotNull(result.sad());
        assertNotNull(result.userID());
    }

    private InstancioApi<SignHashRequestDto> aDto() {
        List<String> hashes = List.of(
                Base64.getEncoder().encodeToString("hash1".getBytes()),
                Base64.getEncoder().encodeToString("hash2".getBytes())
        );

        return Instancio.of(SignHashRequestDto.class)
                        .set(field(SignHashRequestDto::getCredentialID), UUID.randomUUID().toString())
                        .set(field(SignHashRequestDto::getHashes), hashes)
                        .set(field(SignHashRequestDto::getSignAlgo), "1.2.840.113549.1.1.11") // SHA256WithRSA
                        .set(field(SignHashRequestDto::getHashAlgorithmOID), null)
                        .set(field(SignHashRequestDto::getSignAlgoParams), null)
                        .set(field(SignHashRequestDto::getOperationMode), "S")
                        .set(field(SignHashRequestDto::getClientData), "test-client-data")
                        .set(field(BaseSignatureRequestDto.class, "SAD"), null);
    }
}