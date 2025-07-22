package com.czertainly.csc.api.mappers.credentials;

import com.czertainly.csc.api.management.RemoveCredentialDto;
import com.czertainly.csc.common.exceptions.InvalidInputDataException;
import com.czertainly.csc.model.CertificateRevocationReason;
import com.czertainly.csc.model.csc.requests.RemoveCredentialRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

public class RemoveCredentialRequestMapperTest {

    RemoveCredentialRequestMapper mapper = new RemoveCredentialRequestMapper();

    @Test
    void canMapRequest() {
        // given
        UUID credentialID = UUID.randomUUID();
        RemoveCredentialDto dto = new RemoveCredentialDto(
                credentialID.toString(),
                CertificateRevocationReason.UNSPECIFIED
        );

        // when
        RemoveCredentialRequest request = mapper.map(dto);

        // then
        assertNotNull(request);
        assertEquals(credentialID, request.credentialID());
        assertEquals(CertificateRevocationReason.UNSPECIFIED, request.revocationReason());
    }

    @Test
    void throwsWhenCredentialIdNotProvided() {
        // given
        RemoveCredentialDto dto = new RemoveCredentialDto(
                null,
                null
        );

        // when
        Executable ex = () -> mapper.map(dto);

        // then
        assertThrows(InvalidInputDataException.class, ex, "Missing string parameter credentialID.");
    }

}
