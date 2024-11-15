package com.czertainly.csc.model.csc;

import com.czertainly.csc.model.signserver.CryptoTokenKey;

public record SignatureQualifierBasedCredentialMetadata(
        String userId,
        CryptoTokenKey key,
        String endEntityName,
        String signatureQualifier,
        int multisign
){}
