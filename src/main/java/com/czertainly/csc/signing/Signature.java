package com.czertainly.csc.signing;

import com.czertainly.csc.signing.configuration.SignaturePackaging;

public record Signature(
        byte[] value,
        SignaturePackaging packaging
) {

    public static Signature of(byte[] value, SignaturePackaging packaging) {
        return new Signature(value, packaging);
    }
}
