package com.czertainly.csc.common.utils;

import com.czertainly.csc.model.csc.CertificateReturnType;

public final class CertificateMapperUtil {

    private CertificateMapperUtil() {}

    public static CertificateReturnType resolveCertificateReturnType(String certificateReturnType)
            throws IllegalArgumentException {
        if (certificateReturnType == null) {
            return CertificateReturnType.END_CERTIFICATE;
        }
        return switch (certificateReturnType) {
            case "none" -> CertificateReturnType.NONE;
            case "single" -> CertificateReturnType.END_CERTIFICATE;
            case "chain" -> CertificateReturnType.CERTIFICATE_CHAIN;
            default -> throw new IllegalArgumentException("Invalid certificateReturnType value.");
        };
    }
}
