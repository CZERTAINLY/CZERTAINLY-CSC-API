package com.czertainly.csc.model;

import com.czertainly.csc.signing.configuration.SignaturePackaging;

public record DocumentSignature (
        byte[] value,
        SignaturePackaging packaging
) implements Signature {

    public static DocumentSignature of(byte[] value, SignaturePackaging packaging) {
        return new DocumentSignature(value, packaging);
    }
}
