package com.czertainly.csc.api.auth.authn;

import com.czertainly.csc.api.auth.CscAuthenticationToken;
import com.czertainly.csc.utils.jwt.TestJWTs;
import com.czertainly.csc.utils.jwt.TestJwtBuilder;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Set;
import java.util.UUID;

class CscJwtAuthenticationConverterTest {

    CscJwtAuthenticationConverter converter = new CscJwtAuthenticationConverter();
    TestJwtBuilder jwtBuilder = new TestJwtBuilder();

    private static final String userID = "franta.pepa.jednicka";
    private static final Integer numOfSignatures = 1;
    private static final String signatureQualifier = "eu_eidas_aes";
    private static final String credentialID = UUID.randomUUID().toString();
    private static final String hashAlgorithmOID = NISTObjectIdentifiers.id_sha256.getId();
    private static final Set<String> hashes = Set.of(
            "pZGm1Av0IEBKARczz7exkNYsZb8LzaMrV7J32a2fFG4=",
            "Njy1yEOux68lDklWf 4nBjiMpXLAyZHqqMOxFcM3Ojo="
    );
    private static final String clientData = "customClientData";


    @Test
    public void canParseCredentialToken() {
        // given
        var jwt = TestJWTs.credentialToken(userID, credentialID, signatureQualifier, numOfSignatures, hashAlgorithmOID,
                                           hashes, clientData
        );

        // when
        CscAuthenticationToken token = convert(jwt);

        // then
        Assertions.assertEquals(jwt, token.getToken());
        Assertions.assertTrue(token.getAuthorities().stream().map(Object::toString).anyMatch(CscJwtAuthenticationConverter.CREDENTIAL_SCOPE::equalsIgnoreCase));

        Assertions.assertNotNull(token.getSignatureActivationData());
        Assertions.assertEquals(userID, token.getSignatureActivationData().getUserID().get());
        Assertions.assertEquals(credentialID, token.getSignatureActivationData().getCredentialID().get());
        Assertions.assertEquals(signatureQualifier, token.getSignatureActivationData().getSignatureQualifier().get());
        Assertions.assertEquals(numOfSignatures, token.getSignatureActivationData().getNumSignatures());
        Assertions.assertEquals(hashes, token.getSignatureActivationData().getHashes().get());
        Assertions.assertEquals(hashAlgorithmOID, token.getSignatureActivationData().getHashAlgorithmOID().get());
        Assertions.assertEquals(clientData, token.getSignatureActivationData().getClientData().get());
    }

    @Test
    public void canParseNonCredentialToken() {
        // given
        var jwt = TestJWTs.serviceToken();

        // when
        CscAuthenticationToken token = convert(jwt);

        // then
        Assertions.assertEquals(jwt, token.getToken());
        Assertions.assertTrue(token.getAuthorities().stream().map(Object::toString).anyMatch("SCOPE_service"::equalsIgnoreCase));

        Assertions.assertNull(token.getSignatureActivationData());
    }

    private CscAuthenticationToken convert(Jwt jwt) {
        var token = converter.convert(jwt);
        Assertions.assertInstanceOf(CscAuthenticationToken.class, token);
        return (CscAuthenticationToken) token;
    }

}