package com.czertainly.csc.api.management;

public record RekeyCredentialDto(
        String credentialID,
        String cryptoTokenName,
        String keyAlgorithm,
        String csrSignatureAlgorithm,
        String keySpecification
) {

}
