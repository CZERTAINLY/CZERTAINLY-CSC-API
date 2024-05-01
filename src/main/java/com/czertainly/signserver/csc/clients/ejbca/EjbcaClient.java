package com.czertainly.signserver.csc.clients.ejbca;

import com.czertainly.signserver.csc.clients.ejbca.ws.EjbcaWsClient;
import com.czertainly.signserver.csc.clients.ejbca.ws.dto.CertificateRequestResponse;
import com.czertainly.signserver.csc.clients.ejbca.ws.dto.CertificateResponse;
import com.czertainly.signserver.csc.common.exceptions.RemoteSystemException;
import com.czertainly.signserver.csc.common.result.ErrorWithDescription;
import com.czertainly.signserver.csc.common.result.Result;
import com.czertainly.signserver.csc.model.ejbca.EndEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.ws.soap.client.SoapFaultClientException;

import java.time.Period;
import java.time.ZonedDateTime;

@Component
public class EjbcaClient {

    private static final Logger logger = LoggerFactory.getLogger(EjbcaClient.class);

    private final EjbcaWsClient ejbcaWsClient;
    private final Period certificateValidity;

    public EjbcaClient(EjbcaWsClient ejbcaWsClient,
                       @Value("${ejbca.certificateValidityDays}") int certificateValidityDays
    ) {
        this.ejbcaWsClient = ejbcaWsClient;
        this.certificateValidity = Period.ofDays(certificateValidityDays);
    }

    public void createEndEntity(EndEntity endEntity) {
        ejbcaWsClient.editUser(endEntity.username(), endEntity.password(), endEntity.subjectDN());
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