package com.czertainly.csc.clients.ejbca;

import com.czertainly.csc.clients.ejbca.ws.dto.CertificateResponse;
import com.czertainly.csc.model.ejbca.EndEntity;
import com.czertainly.csc.clients.ejbca.ws.EjbcaWsClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Period;
import java.time.ZonedDateTime;

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
        return response.getData();
    }
}