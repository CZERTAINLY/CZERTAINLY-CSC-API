package com.czertainly.csc.api.mappers.credentials;

import com.czertainly.csc.api.management.RekeyCredentialDto;
import com.czertainly.csc.common.exceptions.InvalidInputDataException;
import com.czertainly.csc.model.csc.requests.RekeyCredentialRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class RekeyCertificateRequestMapperTest {

    RekeyCertificateRequestMapper mapper = new RekeyCertificateRequestMapper();

    @Test
    void canMapRequest() {
        // given
        UUID credentialID = UUID.randomUUID();
        RekeyCredentialDto dto = new RekeyCredentialDto(
                credentialID.toString(),
                "long-lasting-credential",
                "crypto-token-name"
        );

        // when
        RekeyCredentialRequest request = mapper.map(dto);

        // then
        assertNotNull(request);
        assertEquals(credentialID, request.credentialID());
        assertEquals("crypto-token-name", request.cryptoTokenName());
        assertEquals("long-lasting-credential", request.credentialProfileName());
    }

    @Test
    void throwsWhenCredentialIdNotProvided() {
        // given
        RekeyCredentialDto dto = new RekeyCredentialDto(
                null,
                "long-lasting-credential",
                "crypto-token-name"
        );

        // when
        Executable ex = () -> mapper.map(dto);

        // then
        assertThrows(InvalidInputDataException.class, ex, "Missing string parameter credentialID.");
    }

    @Test
    void throwsWhenCredentialIdIsInvalid() {
        // given
        RekeyCredentialDto dto = new RekeyCredentialDto(
                "long-lasting-credential",
                "invalid-uuid",
                "crypto-token-name"
        );

        // when
        Executable ex = () -> mapper.map(dto);

        // then
        assertThrows(InvalidInputDataException.class, ex, "Invalid parameter credentialID.");
    }

}