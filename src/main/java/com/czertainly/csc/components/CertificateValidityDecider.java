package com.czertainly.csc.components;

import com.czertainly.csc.clients.ejbca.EjbcaClient;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.model.csc.CertificateStatus;
import org.bouncycastle.cert.X509CertificateHolder;
import org.springframework.stereotype.Component;

import java.time.DateTimeException;
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

    public Result<CertificateStatus, TextError> decideStatus(X509CertificateHolder certificate) {

        return decideCertificateExpirationStatus(certificate)
                .flatMap(expirationStatus -> {
                    if (expirationStatus == CertificateStatus.VALID) {
                        return getRevocationStatus(certificate)
                                .mapError(e -> e.extend("Failed to obtain revocation status for certificate."));
                    }
                    return Result.success(expirationStatus);
                });
    }

    private Result<CertificateStatus, TextError> decideCertificateExpirationStatus(X509CertificateHolder certificate) {
        try {
            ZonedDateTime notBefore = dateConverter.dateToZonedDateTime(certificate.getNotBefore(), utcZoneId);
            ZonedDateTime notAfter = dateConverter.dateToZonedDateTime(certificate.getNotAfter(), utcZoneId);
            ZonedDateTime now = ZonedDateTime.now();
            if (now.isBefore(notBefore)) {
                return Result.success(CertificateStatus.NOT_YET_VALID);
            } else if (now.isAfter(notAfter)) {
                return Result.success(CertificateStatus.EXPIRED);
            }
            return Result.success(CertificateStatus.VALID);
        } catch (DateTimeException e) {
            return Result.error(new TextError("Failed to parse certificate validity dates."));
        }
    }

    private Result<CertificateStatus, TextError> getRevocationStatus(X509CertificateHolder certificate) {
        try {
            String serialNumberHex = certificate.getSerialNumber().toString(16);
            String issuerDn = certificate.getIssuer().toString();

            return ejbcaClient.getCertificateRevocationStatus(serialNumberHex, issuerDn)
                              .map(revocationStatus -> switch (revocationStatus) {
                                  case REVOKED -> CertificateStatus.REVOKED;
                                  case SUSPENDED -> CertificateStatus.SUSPENDED;
                                  case NOT_REVOKED -> CertificateStatus.VALID;
                              });
        } catch (Exception e) {
            return Result.error(TextError.of(e));
        }
    }
}
