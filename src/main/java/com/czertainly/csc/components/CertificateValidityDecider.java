package com.czertainly.csc.components;

import com.czertainly.csc.clients.ejbca.EjbcaClient;
import com.czertainly.csc.model.RevocationStatus;
import com.czertainly.csc.model.csc.CertificateStatus;
import org.springframework.stereotype.Component;

import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.time.ZonedDateTime;

@Component
public class CertificateValidityDecider {

    private final DateConverter dateConverter;

    private final EjbcaClient ejbcaClient;

    private final ZoneId utcZoneId = ZoneId.of("UTC");

    public CertificateValidityDecider(DateConverter dateConverter, EjbcaClient ejbcaClient) {
        this.dateConverter = dateConverter;
        this.ejbcaClient = ejbcaClient;
    }

    public CertificateStatus decideStatus(X509Certificate certificate) {
        CertificateStatus status = checkCertificateExpiration(certificate);
        if (status != null) return status;

        String serialNumberHex = certificate.getSerialNumber().toString(16);
        String issuerDn = certificate.getIssuerX500Principal().getName();
        RevocationStatus revocationStatus = ejbcaClient.getCertificateRevocationStatus(serialNumberHex, issuerDn);

        return switch (revocationStatus) {
            case REVOKED -> CertificateStatus.REVOKED;
            case SUSPENDED -> CertificateStatus.SUSPENDED;
            case NOT_REVOKED -> CertificateStatus.VALID;
        };
    }

    private CertificateStatus checkCertificateExpiration(X509Certificate certificate) {
        ZonedDateTime notBefore = dateConverter.dateToZonedDateTime(certificate.getNotBefore(), utcZoneId);
        ZonedDateTime notAfter = dateConverter.dateToZonedDateTime(certificate.getNotAfter(), utcZoneId);
        ZonedDateTime now = ZonedDateTime.now();
        if (now.isBefore(notBefore)) {
            return CertificateStatus.NOT_YET_VALID;
        } else if (now.isAfter(notAfter)) {
            return CertificateStatus.EXPIRED;
        }
        return null;
    }
}
