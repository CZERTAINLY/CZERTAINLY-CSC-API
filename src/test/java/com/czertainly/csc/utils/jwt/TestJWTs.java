package com.czertainly.csc.utils.jwt;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static com.czertainly.csc.utils.jwt.Constants.CREDENTIAL_SCOPE;
import static com.czertainly.csc.utils.jwt.Constants.SERVICE_SCOPE;

public class TestJWTs {

    public static Jwt credentialToken() {
        return new TestJwtBuilder().withScope(CREDENTIAL_SCOPE)
                                   .withUserID("franta.pepa.jednicka")
                                   .withNumOfSignatures("1")
                                   .withSignatureQualifier("eu_eidas_aes")
                                   .withCredentialID(UUID.randomUUID().toString())
                                   .withHashAlgorithmOID(NISTObjectIdentifiers.id_sha256.getId())
                                   .withHashes(
                                           Set.of(
                                                   "pZGm1Av0IEBKARczz7exkNYsZb8LzaMrV7J32a2fFG4=",
                                                   "Njy1yEOux68lDklWf 4nBjiMpXLAyZHqqMOxFcM3Ojo="
                                           )
                                   )
                                   .build();
    }

    public static Jwt credentialToken(String userID, String credentialID, String signatureQualifier,
                                      Integer numOfSignatures, String hashAlgorithmOID, Set<String> hashes,
                                      String clientData
    ) {
        return new TestJwtBuilder().withScope(CREDENTIAL_SCOPE)
                                   .withUserID(userID)
                                   .withNumOfSignatures(numOfSignatures.toString())
                                   .withSignatureQualifier(signatureQualifier)
                                   .withCredentialID(credentialID)
                                   .withHashAlgorithmOID(hashAlgorithmOID)
                                   .withHashes(hashes)
                                   .withClaim("clientData", clientData)
                                   .build();
    }

    public static Jwt serviceToken() {
        return new TestJwtBuilder().withScope(SERVICE_SCOPE)
                                   .build();
    }

    public static Jwt serviceToken(Map<String, String> claims) {
        return new TestJwtBuilder().withScope(SERVICE_SCOPE)
                                   .withClaims(claims)
                                   .build();
    }

}
