package com.czertainly.csc.clients.ejbca;

import com.czertainly.csc.clients.ejbca.ws.EjbcaWsClient;
import com.czertainly.csc.clients.ejbca.ws.dto.CertificateResponse;
import com.czertainly.csc.clients.ejbca.ws.dto.RevokeStatus;
import com.czertainly.csc.common.exceptions.RemoteSystemException;
import com.czertainly.csc.model.RevocationStatus;
import com.czertainly.csc.model.ejbca.EndEntity;
import org.apache.commons.lang3.ArrayUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Period;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.Objects;

@Component
public class EjbcaClient {

    private static final Logger logger = LoggerFactory.getLogger(EjbcaClient.class);

    private final EjbcaWsClient ejbcaWsClient;
    private final Period certificateValidity;

    public EjbcaClient(EjbcaWsClient ejbcaWsClient) {
        this.ejbcaWsClient = ejbcaWsClient;
        this.certificateValidity = Period.ofDays(365);
    }

    public void createEndEntity(EndEntity endEntity) {
        ejbcaWsClient.editUser(endEntity.username(), endEntity.password(), endEntity.subjectDN(), endEntity.san());
    }

    /*
     * Returns a byte array containing the signed certificate with complete chain in PKCS7 format.
     */
    public byte[] signCertificateRequest(EndEntity endEntity, byte[] csr) {
        ZonedDateTime validityStart = ZonedDateTime.now();
        ZonedDateTime validityEnd = validityStart.plus(certificateValidity);
        CertificateResponse response = ejbcaWsClient
                .requestCertificate(endEntity.username(), endEntity.password(), endEntity.subjectDN(), csr,
                                    validityStart, validityEnd
                );
        byte[] base64Bytes = response.getData();
        byte[] base64BytesWithoutNewLines = ArrayUtils.removeAllOccurrences(base64Bytes, (byte) '\n');
        return Base64.getDecoder().decode(base64BytesWithoutNewLines);
    }

    public RevocationStatus getCertificateRevocationStatus(String certificateSerialNumberHex, String issuerDN) {
        RevokeStatus status = ejbcaWsClient.checkRevocationStatus(issuerDN, certificateSerialNumberHex);
        if (status.getIssuerDN() == null || status.getCertificateSN() == null) {
            throw new RemoteSystemException(
                    String.format("Certificate %s issued by %s not found in EJBCA", certificateSerialNumberHex,
                                  issuerDN
                    ));
        }
        if (!Objects.equals(status.getIssuerDN(), issuerDN)) {
            throw new RemoteSystemException(String.format(
                    "Revocation status for different certificate received. Issuer of requested certificate is %s, but received for certificate issued by %s",
                    certificateSerialNumberHex, status.getCertificateSN()
            ));
        }
        if (!Objects.equals(status.getCertificateSN(), certificateSerialNumberHex)) {
            throw new RemoteSystemException(String.format(
                    "Revocation status for different certificate received. Requested for %s, received for %s",
                    certificateSerialNumberHex, status.getCertificateSN()
            ));
        }
        if (status.getReason() == 6) {
            return RevocationStatus.SUSPENDED;
        }
        return status.getReason() == -1 ? RevocationStatus.NOT_REVOKED : RevocationStatus.REVOKED;
    }

    public EndEntity getEndEntity(String username) {
        var data = ejbcaWsClient.getUserData(username);
        if (data == null) {
            return null;
        }

        return new EndEntity(data.getUsername(), data.getPassword(), data.getSubjectDN(), data.getSubjectAltName());
    }
}