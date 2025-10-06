package com.czertainly.csc.model.csc;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.util.List;


public record KeyInfo(
        KeyStatus status,
        List<ASN1ObjectIdentifier> algo,
        Integer len,
        String curve
) {
}
