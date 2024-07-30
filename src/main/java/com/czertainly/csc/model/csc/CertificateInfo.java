package com.czertainly.csc.model.csc;

import java.time.ZonedDateTime;
import java.util.List;

public record CertificateInfo(
        CertificateStatus status,
        List<byte[]> certificates,
        String serialNumber,
        String issuerDN,
        String subjectDN,
        ZonedDateTime validFrom,
        ZonedDateTime validTo
) {
}
