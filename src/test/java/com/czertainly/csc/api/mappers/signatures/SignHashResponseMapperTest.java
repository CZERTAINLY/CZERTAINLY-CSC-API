package com.czertainly.csc.api.mappers.signatures;

import com.czertainly.csc.api.signhash.SignHashResponseDto;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.model.PlainSignature;
import com.czertainly.csc.model.Signatures;
import com.czertainly.csc.model.SignaturesContainer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.List;

import static com.czertainly.csc.utils.assertions.ResultAssertions.assertSuccessAndGet;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class SignHashResponseMapperTest {

    private SignHashResponseMapper mapper;

    @BeforeEach
    void setUp() {
        mapper = new SignHashResponseMapper();
    }

    @Test
    void shouldMapSingleSignatureSuccessfully() {
        // given
        byte[] signatureValue = "test-signature".getBytes();
        String signatureValueB64 = Base64.getEncoder().encodeToString(signatureValue);
        PlainSignature signature = PlainSignature.of(signatureValue);
        SignaturesContainer<PlainSignature> container = Signatures.of(signature);

        // when
        Result<SignHashResponseDto, TextError> result = mapper.map(container);

        // then
        SignHashResponseDto response = assertSuccessAndGet(result);
        assertNotNull(response);
        assertNotNull(response.getSignatures());
        assertEquals(1, response.getSignatures().size());

        assertEquals(signatureValueB64, response.getSignatures().getFirst());
    }

    @Test
    void shouldMapMultipleSignaturesAndPreserveOrderSuccessfully() {
        // given
        byte[] signature1 = "first-signature".getBytes();
        byte[] signature2 = "second-signature".getBytes();
        byte[] signature3 = "third-signature".getBytes();

        List<PlainSignature> signatures = List.of(
                PlainSignature.of(signature1),
                PlainSignature.of(signature2),
                PlainSignature.of(signature3)
        );
        SignaturesContainer<PlainSignature> container = Signatures.of(signatures);

        // when
        Result<SignHashResponseDto, TextError> result = mapper.map(container);

        // then
        SignHashResponseDto response = assertSuccessAndGet(result);
        assertNotNull(response);
        assertEquals(3, response.getSignatures().size());

        Base64.Encoder encoder = Base64.getEncoder();
        assertEquals(encoder.encodeToString(signature1), response.getSignatures().get(0));
        assertEquals(encoder.encodeToString(signature2), response.getSignatures().get(1));
        assertEquals(encoder.encodeToString(signature3), response.getSignatures().get(2));
    }

    @Test
    void shouldMapBinaryDataCorrectly() {
        // given
        byte[] binaryData = new byte[]{0x00, 0x01, 0x02, (byte) 0xFF, (byte) 0xFE, (byte) 0xFD};
        PlainSignature signature = PlainSignature.of(binaryData);
        SignaturesContainer<PlainSignature> container = Signatures.of(signature);

        // when
        Result<SignHashResponseDto, TextError> result = mapper.map(container);

        // then
        SignHashResponseDto response = assertSuccessAndGet(result);
        assertNotNull(response);
        assertEquals(1, response.getSignatures().size());

        String expectedEncoded = Base64.getEncoder().encodeToString(binaryData);
        assertEquals(expectedEncoded, response.getSignatures().getFirst());
    }
}