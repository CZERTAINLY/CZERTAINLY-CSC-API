package com.czertainly.csc.model.csc;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;


public record KeyInfo(
        KeyStatus status,
        ASN1ObjectIdentifier algo,
        Integer len,
        String curve
) {
}
