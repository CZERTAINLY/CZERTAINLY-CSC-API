package com.czertainly.signserver.csc.clients.ejbca;

import com.czertainly.signserver.csc.clients.ejbca.ws.EjbcaWsClient;
import com.czertainly.signserver.csc.clients.ejbca.ws.dto.CertificateRequestResponse;
import com.czertainly.signserver.csc.clients.ejbca.ws.dto.EditUserResponse;
import com.czertainly.signserver.csc.common.ErrorWithDescription;
import com.czertainly.signserver.csc.common.Result;
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

    public Result<EndEntity, ErrorWithDescription> createEndEntity(EndEntity endEntity) {
        try {
            ejbcaWsClient.editUser(endEntity.username(), endEntity.password(),
                                                               endEntity.subjectDN()
            );

            return Result.ok(endEntity);
        } catch (SoapFaultClientException e) {
            logger.error("Failed to create end entity {}", endEntity.username(), e);
            return Result.error(new ErrorWithDescription("Failed to create end entity", e.getMessage()));
        }
    }

    /*
     * Returns a byte array containing the signed certificate with complete chain in PKCS7 format.
     */
    public Result<byte[], ErrorWithDescription> signCertificateRequest(EndEntity endEntity, byte[] csr) {
        try {
            ZonedDateTime validityStart = ZonedDateTime.now();
            ZonedDateTime validityEnd = validityStart.plus(certificateValidity);
            CertificateRequestResponse response = ejbcaWsClient
                    .requestCertificate(endEntity.username(), endEntity.password(), endEntity.subjectDN(), csr,
                                        validityStart, validityEnd
                    );
            return Result.ok(response.getReturn().getData());
        } catch (SoapFaultClientException e) {
            logger.error("Failed to sign certificate request for user {}", endEntity.username(), e);
            return Result.error(new ErrorWithDescription("Failed to sign certificate request.", e.getMessage()));
        }
    }
}