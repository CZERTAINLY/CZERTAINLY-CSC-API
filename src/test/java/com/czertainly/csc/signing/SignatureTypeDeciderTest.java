package com.czertainly.csc.signing;

import com.czertainly.csc.model.SignDocParameters;
import com.czertainly.csc.utils.signing.aSignDocParameters;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static com.czertainly.csc.utils.assertions.ResultAssertions.*;
import static org.junit.jupiter.api.Assertions.assertEquals;

class SignatureTypeDeciderTest {

    SignatureTypeDecider signatureTypeDecider = new SignatureTypeDecider();

    @Test
    void decidesLongTermSignatureWhenOnlyCredentialIdProvided() {
        // given
        SignDocParameters parameters = aSignDocParameters.instance()
                                                         .withCredentialId(UUID.randomUUID())
                                                         .withSignatureQualifier(null)
                                                         .withSessionId(null)
                                                         .build();

        // when
        var result = signatureTypeDecider.decideType(parameters);

        // then
        SignatureType type = assertSuccessAndGet(result);
        assertEquals(SignatureType.LONG_TERM, type);
    }

    @Test
    void decidesLongTermSignatureWhenCredentialIdAndSignatureQualifierProvided() {
        // given
        SignDocParameters parameters = aSignDocParameters.instance()
                                                         .withCredentialId(UUID.randomUUID())
                                                         .withSignatureQualifier("signatureQualifier")
                                                         .withSessionId(null)
                                                         .build();

        // when
        var result = signatureTypeDecider.decideType(parameters);

        // then
        SignatureType type = assertSuccessAndGet(result);
        assertEquals(SignatureType.LONG_TERM, type);
    }

    @Test
    void decidesOneTimeSignatureWhenOnlySignatureQualifierProvided() {
        // given
        SignDocParameters parameters = aSignDocParameters.instance()
                                                         .withCredentialId(null)
                                                         .withSignatureQualifier("signatureQualifier")
                                                         .withSessionId(null)
                                                         .build();

        // when
        var result = signatureTypeDecider.decideType(parameters);

        // then
        SignatureType type = assertSuccessAndGet(result);
        assertEquals(SignatureType.ONE_TIME, type);
    }

    @Test
    void decidesSessionSignatureWhenSessionIdAndSignatureQualifierProvided() {
        // given
        SignDocParameters parameters = aSignDocParameters.instance()
                                                         .withCredentialId(null)
                                                         .withSignatureQualifier("signatureQualifier")
                                                         .withSessionId(UUID.randomUUID())
                                                         .build();

        // when
        var result = signatureTypeDecider.decideType(parameters);

        // then
        SignatureType type = assertSuccessAndGet(result);
        assertEquals(SignatureType.SESSION, type);
    }

    @Test
    void decidesErrorWhenOnlySessionIdProvided() {
        // given
        SignDocParameters parameters = aSignDocParameters.instance()
                                                         .withCredentialId(null)
                                                         .withSignatureQualifier(null)
                                                         .withSessionId(UUID.randomUUID())
                                                         .build();

        // when
        var result = signatureTypeDecider.decideType(parameters);

        // then
        assertErrorContains(result, "Session ID is present but signature qualifier is missing.");
    }

    @Test
    void decidesErrorWhenSessionIdAndCredentialIdProvided() {
        // given
        SignDocParameters parameters = aSignDocParameters.instance()
                                                         .withCredentialId(UUID.randomUUID())
                                                         .withSignatureQualifier(null)
                                                         .withSessionId(UUID.randomUUID())
                                                         .build();

        // when
        var result = signatureTypeDecider.decideType(parameters);

        // then
        assertErrorContains(result, "Both session ID and credential ID are present.");
    }

    @Test
    void decidesErrorWhenSessionIdAndSignatureQualifierAndCredentialIdProvided() {
        // given
        SignDocParameters parameters = aSignDocParameters.instance()
                                                         .withCredentialId(UUID.randomUUID())
                                                         .withSignatureQualifier("signatureQualifier")
                                                         .withSessionId(UUID.randomUUID())
                                                         .build();

        // when
        var result = signatureTypeDecider.decideType(parameters);

        // then
        assertErrorContains(result, "Session ID, signature qualifier and credential ID must not be present at the same time.");
    }

    @Test
    void decidesErrorWhenNoParametersProvided() {
        // given
        SignDocParameters parameters = aSignDocParameters.instance()
                                                         .withCredentialId(null)
                                                         .withSignatureQualifier(null)
                                                         .withSessionId(null)
                                                         .build();

        // when
        var result = signatureTypeDecider.decideType(parameters);

        // then
        assertErrorContains(result, "Neither session ID nor signature qualifier nor credential ID is present.");
    }
}